const { generateId, generateWalletKey } = require('../utils/pluginUtils');
const expiryTimeout = 5 * 60 * 1000;
const maxLoginAttempts = 5;
const loginChallenges = new Map();
const sessionCache = new Map();
const crypto = require("crypto");

const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../constants/authConstants');

const EmailUserLoginStrategy = require('./user-login-strategies/EmailUserLoginStrategy');
const PasskeyUserLoginStrategy = require('./user-login-strategies/PasskeyUserLoginStrategy');
const TotpUserLoginStrategy = require('./user-login-strategies/TotpUserLoginStrategy');

async function UserLogin() {
    let self = {};
    let persistence = await $$.loadPlugin("StandardPersistence");
    let CreditManager = await $$.loadPlugin("CreditManager");
    const webauthnUtils = require("../authenticator/webauthn");

    const strategies = {
        [AUTH_TYPES.EMAIL]: new EmailUserLoginStrategy(persistence, webauthnUtils, crypto, loginChallenges),
        [AUTH_TYPES.PASSKEY]: new PasskeyUserLoginStrategy(persistence, webauthnUtils, crypto, loginChallenges),
        [AUTH_TYPES.TOTP]: new TotpUserLoginStrategy(persistence, webauthnUtils, crypto, loginChallenges)
    };

    function getStrategy(authType) {
        return strategies[authType] || strategies[AUTH_TYPES.EMAIL];
    }

    self.persistence = persistence;

    self.userExists = async function (email) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (userExists) {
            let user = await persistence.getUserLoginStatus(email);
            if (!user.authTypes && user.activeAuthType) {
                user.authTypes = [user.activeAuthType];
                await persistence.updateUserLoginStatus(user.id, user);
            }

            const defaultAuthType = user.authTypes && user.authTypes.length > 0 ? user.authTypes[0] : AUTH_TYPES.EMAIL;
            const strategy = getStrategy(defaultAuthType);
            const strategyResult = await strategy.handleUserExists(user);

            if (user.passkeyCredentials && user.passkeyCredentials.length > 0 && defaultAuthType !== AUTH_TYPES.PASSKEY) {
                const passkeyStrategy = getStrategy(AUTH_TYPES.PASSKEY);
                const passkeyResult = await passkeyStrategy.handleUserExists(user);

                if (passkeyResult.publicKeyCredentialRequestOptions) {
                    strategyResult.publicKeyCredentialRequestOptions = passkeyResult.publicKeyCredentialRequestOptions;
                }
                if (passkeyResult.challengeKey) {
                    strategyResult.challengeKey = passkeyResult.challengeKey;
                }
            }

            return {
                status: STATUS.SUCCESS,
                userExists: true,
                authTypes: user.authTypes || [AUTH_TYPES.EMAIL],
                ...strategyResult
            };
        }
        return {
            status: STATUS.SUCCESS,
            userExists: false,
            authTypes: [AUTH_TYPES.EMAIL]
        };
    }

    self.createUser = async function (email, name, referrerId, defaultAuthType, registrationData) {
        let walletKey = generateWalletKey();
        name = name || email.split("@")[0];
        let userAsset = await CreditManager.addUser(email, name, referrerId);
        defaultAuthType = defaultAuthType || AUTH_TYPES.EMAIL;
        const strategy = getStrategy(defaultAuthType);

        let userPayload = {
            globalUserId: userAsset.id,
            email: email,
            walletKey: walletKey,
            authTypes: [defaultAuthType],
            passkeyCredentials: [],
            totpSecret: undefined,
            totpEnabled: false,
            totpPendingSetup: false,
            validationEmailCode: undefined,
            validationEmailCodeTimestamp: undefined,
            loginAttempts: 0,
            lastLoginAttempt: null
        };

        await strategy.handleCreateUser(userPayload, registrationData);

        let user = await persistence.createUserLoginStatus(userPayload);
        user.status = STATUS.SUCCESS;
        return user;
    }

    self.setUpFounderLogin = async function (email, name, founderId) {
        let walletKey = generateWalletKey();
        defaultAuthType = AUTH_TYPES.EMAIL;
        const strategy = getStrategy(defaultAuthType);
        let userPayload = {
            globalUserId: founderId,
            email: email,
            walletKey: walletKey,
            authTypes: [defaultAuthType],
            passkeyCredentials: [],
            totpSecret: undefined,
            totpEnabled: false,
            totpPendingSetup: false,
            validationEmailCode: undefined,
            validationEmailCodeTimestamp: undefined,
            loginAttempts: 0,
            lastLoginAttempt: null
        };
        await strategy.handleCreateUser(userPayload);

        let user = await persistence.createUserLoginStatus(userPayload);
        return user;
    }
    self.registerNewPasskey = async function (email, registrationData) {
        let user = await persistence.getUserLoginStatus(email);
        if (!user) {
            throw new Error(ERROR_REASONS.USER_NOT_EXISTS);
        }

        const strategy = strategies[AUTH_TYPES.PASSKEY];
        if (!strategy || typeof strategy.handleRegisterNewPasskey !== 'function') {
            throw new Error("Passkey strategy not available or invalid.");
        }

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (!user.authTypes.includes(AUTH_TYPES.EMAIL)) {
            user.authTypes.push(AUTH_TYPES.EMAIL);
        }

        try {
            const result = await strategy.handleRegisterNewPasskey(user, registrationData);

            if (!user.authTypes.includes(AUTH_TYPES.PASSKEY)) {
                user.authTypes.push(AUTH_TYPES.PASSKEY);
                await persistence.updateUserLoginStatus(user.id, user);
            }

            return result;
        } catch (e) {
            console.error("Error during registerNewPasskey handling:", e);
            throw e;
        }
    }

    async function createSessionForUser(user) {
        let sessionId = generateId(32);
        await persistence.createSession({
            userLoginId: user.id,
            sessionId: sessionId
        });
        sessionCache.set(sessionId, {
            userLoginId: user.id,
            globalUserId: user.globalUserId,
            email: user.email,
            walletKey: user.walletKey,
            authTypes: user.authTypes,
            sessionId: sessionId
        });

        console.log("DEBUG----------: sessionCache", sessionCache);
        return sessionId;
    }

    self.authorizeUser = async function (email, loginData, challengeKey, loginMethod = "") {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.ACCOUNT_NOT_EXISTS };
        }
        let user = await persistence.getUserLoginStatus(email);
        let now = new Date().getTime();

        if (user.loginAttempts >= maxLoginAttempts) {
            if (user.lastLoginAttempt && now < user.lastLoginAttempt + expiryTimeout) {
                return {
                    status: STATUS.FAILED,
                    reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                    lockTime: user.lastLoginAttempt + expiryTimeout - now
                };
            } else {
                await self.resetLoginAttempts(email);
                user = await persistence.getUserLoginStatus(email);
            }
        }

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (!user.authTypes.includes(AUTH_TYPES.EMAIL)) {
            user.authTypes.push(AUTH_TYPES.EMAIL);
            await persistence.updateUserLoginStatus(user.id, user);
        }

        if (loginMethod && !user.authTypes.includes(loginMethod)) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.AUTH_METHOD_NOT_AVAILABLE
            };
        }

        const authMethodToUse = loginMethod || (user.authTypes.length > 0 ? user.authTypes[0] : AUTH_TYPES.EMAIL);
        const strategy = getStrategy(authMethodToUse);

        let verificationResult;
        try {
            verificationResult = await strategy.handleAuthorizeUser(user, loginData, challengeKey);
        } catch (e) {
            console.error(`Error during ${authMethodToUse} authorization strategy:`, e);
            await self.incrementLoginAttempts(email);
            return { status: STATUS.FAILED, reason: `Authorization error: ${e.message}` };
        }

        if (verificationResult.verified) {
            user.loginAttempts = 0;
            user.lastLoginAttempt = null;

            if (verificationResult.update && typeof verificationResult.update === 'object') {
                Object.assign(user, verificationResult.update);
            }
            await persistence.updateUserLoginStatus(user.id, user);
            let sessionId = await createSessionForUser(user);

            return {
                status: STATUS.SUCCESS,
                sessionId: sessionId,
                email: email,
                walletKey: user.walletKey,
                userInfo: user.userInfo,
                userId: user.globalUserId
            };
        } else {
            await self.incrementLoginAttempts(email);
            return { status: STATUS.FAILED, reason: verificationResult.reason || ERROR_REASONS.INVALID_CREDENTIALS };
        }
    }

    self.getUserValidationEmailCode = async function (email, name, referrerId) {
        let userExists = await persistence.hasUserLoginStatus(email);
        let user;

        if (!userExists) {
            user = await self.createUser(email, name, referrerId, AUTH_TYPES.EMAIL, null);
            return {
                status: STATUS.SUCCESS,
                code: user.validationEmailCode,
                walletKey: user.walletKey,
                authTypes: user.authTypes || [AUTH_TYPES.EMAIL]
            };
        }

        user = await persistence.getUserLoginStatus(email);

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const strategy = getStrategy(AUTH_TYPES.EMAIL);

        if (user.loginAttempts >= maxLoginAttempts) {
            if (user.lastLoginAttempt && new Date().getTime() < user.lastLoginAttempt + expiryTimeout) {
                return {
                    status: STATUS.FAILED,
                    reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                    lockTime: user.lastLoginAttempt + expiryTimeout - new Date().getTime()
                };
            }
            await self.resetLoginAttempts(email);
            user = await persistence.getUserLoginStatus(email);
        }

        return await strategy.handleGetUserValidationCode(user);
    };

    self.checkSessionId = async function (sessionId) {
        if (sessionCache.has(sessionId)) {
            return { status: STATUS.SUCCESS, ...sessionCache.get(sessionId) };
        }

        let sessionExists = await persistence.hasSession(sessionId);
        if (!sessionExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.SESSION_NOT_EXISTS };
        }
        let session = await persistence.getSession(sessionId);
        console.log("DEBUG----------: session", session);
        let userExists = await persistence.hasUserLoginStatus(session.userLoginId);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_SESSION_NOT_EXISTS };
        }
        let user = await persistence.getUserLoginStatus(session.userLoginId);

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const sessionData = {
            globalUserId: user.globalUserId,
            email: user.email,
            walletKey: user.walletKey,
            authTypes: user.authTypes
        };

        sessionCache.set(sessionId, { userLoginId: user.id, ...sessionData });

        return {
            status: STATUS.SUCCESS,
            ...sessionData
        };
    }

    self.logout = async function (sessionId) {
        try {
            await persistence.deleteSession(sessionId);
            sessionCache.delete(sessionId);
            return { status: STATUS.SUCCESS };
        } catch (e) {
            console.error(`Error deleting session ${sessionId}:`, e);
            return { status: STATUS.SUCCESS, error: "Failed to delete session server-side" };
        }
    }

    self.isSysAdmin = async function (email) {
        return process.env.SYSADMIN_EMAIL === email;
    }

    self.getUserInfo = async function (email) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }
        let user = await persistence.getUserLoginStatus(email);

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const userInfoPayload = {
            ...(user.userInfo || {}),
            email: user.email,
            authTypes: user.authTypes,
            totpEnabled: user.totpEnabled,
            totpPendingSetup: user.totpPendingSetup,
            passkeyCredentials: (user.passkeyCredentials || []).map(cred => ({
                id: cred.id,
                name: cred.name,
                createdAt: cred.createdAt,
                transports: cred.transports
            }))
        };
        return {
            status: STATUS.SUCCESS,
            userInfo: userInfoPayload
        };
    }

    self.deletePasskey = async function (email, credentialId) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }

        let user = await persistence.getUserLoginStatus(email);

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const strategy = strategies[AUTH_TYPES.PASSKEY];
        if (!strategy || typeof strategy.handleDeletePasskey !== 'function') {
            throw new Error("Passkey strategy not available or invalid.");
        }

        try {
            return await strategy.handleDeletePasskey(user, credentialId);
        } catch (e) {
            console.error(`Error deleting passkey for ${email}:`, e);
            return { status: STATUS.FAILED, reason: `Failed to delete passkey: ${e.message}` };
        }
    }

    self.deleteTotp = async function (email) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }

        let user = await persistence.getUserLoginStatus(email);

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const strategy = strategies[AUTH_TYPES.TOTP];
        if (!strategy || typeof strategy.handleDeleteTotp !== 'function') {
            throw new Error("TOTP strategy not available or invalid.");
        }

        try {
            return await strategy.handleDeleteTotp(user);
        } catch (e) {
            console.error(`Error deleting TOTP for ${email}:`, e);
            return { status: STATUS.FAILED, reason: `Failed to delete TOTP: ${e.message}` };
        }
    }

    self.setUserInfo = async function (email, userInfo) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }
        let user = await persistence.getUserLoginStatus(email);
        user.userInfo = { ...(user.userInfo || {}), ...userInfo };
        await persistence.updateUserLoginStatus(user.id, user);
        return { status: STATUS.SUCCESS };
    }

    self.incrementLoginAttempts = async function (email) {
        try {
            let user = await persistence.getUserLoginStatus(email);
            user.loginAttempts = (user.loginAttempts || 0) + 1;
            user.lastLoginAttempt = new Date().getTime();
            await persistence.updateUserLoginStatus(user.id, user);
        } catch (e) {
            console.error(`Failed to increment login attempts for ${email}:`, e);
        }
    }

    self.resetLoginAttempts = async function (email) {
        try {
            let user = await persistence.getUserLoginStatus(email);
            user.loginAttempts = 0;
            user.lastLoginAttempt = null;
            await persistence.updateUserLoginStatus(user.id, user);
        } catch (e) {
            console.error(`Failed to reset login attempts for ${email}:`, e);
        }
    }

    self.shutDown = async function () {
        await persistence.shutDown();
        return { status: STATUS.SUCCESS };
    }

    self.setTotpSecret = async function (email, secret) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }
        let user = await persistence.getUserLoginStatus(email);

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const strategy = strategies[AUTH_TYPES.TOTP];
        if (!strategy || typeof strategy.handleSetTotpSecret !== 'function') {
            throw new Error("TOTP strategy not available or invalid.");
        }
        try {
            await strategy.handleSetTotpSecret(user, secret);
            return { status: STATUS.SUCCESS };
        } catch (e) {
            console.error(`Error setting TOTP secret for ${email}:`, e);
            return { status: STATUS.FAILED, reason: `Failed to set TOTP secret: ${e.message}` };
        }
    }

    self.verifyAndEnableTotp = async function (email, token) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }
        let user = await persistence.getUserLoginStatus(email);

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (!user.authTypes.includes(AUTH_TYPES.EMAIL)) {
            user.authTypes.push(AUTH_TYPES.EMAIL);
        }

        const strategy = strategies[AUTH_TYPES.TOTP];
        if (!strategy || typeof strategy.handleVerifyAndEnableTotp !== 'function') {
            throw new Error("TOTP strategy not available or invalid.");
        }

        try {
            const result = await strategy.handleVerifyAndEnableTotp(user, token);
            if (result.verified) {
                if (!user.authTypes.includes(AUTH_TYPES.TOTP)) {
                    user.authTypes.push(AUTH_TYPES.TOTP);
                    await persistence.updateUserLoginStatus(user.id, user);
                }
                return { status: STATUS.SUCCESS };
            } else {
                return { status: STATUS.FAILED, reason: result.reason || ERROR_REASONS.INVALID_TOTP_CODE };
            }
        } catch (e) {
            console.error(`Error verifying/enabling TOTP for ${email}:`, e);
            return { status: STATUS.FAILED, reason: `Verification error: ${e.message}` };
        }
    }

    return self;
}

let singletonInstance = undefined;

module.exports = {
    getInstance: async function () {
        if (!singletonInstance) {
            singletonInstance = await UserLogin();
        }
        return singletonInstance;
    },
    getAllow: function () {
        return async function (globalUserId, email, command, ...args) {
            let user;
            switch (command) {
                case "userExists":
                case "createUser":
                case "checkSessionId":
                case "logout":
                case "isSysAdmin":
                    return true;
                case "setUpFounderLogin":
                    let CreditManager = await $$.loadPlugin("CreditManager");
                    let founder = await CreditManager.getUser(globalUserId);
                    if (founder) {
                        return true;
                    }
                    return false;
                case "authorizeUser":
                case "registerNewPasskey":
                case "getUserInfo":
                case "deletePasskey":
                case "deleteTotp":
                case "setUserInfo":
                case "incrementLoginAttempts":
                case "resetLoginAttempts":
                case "setTotpSecret":
                case "verifyAndEnableTotp":
                    user = await singletonInstance.persistence.getUserLoginStatus(email)
                    if (user.globalUserId === globalUserId) {
                        return true;
                    }
                    return false;
                case "getUserValidationEmailCode":
                    user = await singletonInstance.persistence.getUserLoginStatus(email)
                    if (!user || (user && user.globalUserId === globalUserId)) {
                        return true;
                    }
                    return false;
                default:
                    return false;
            }
        }
    },
    getDependencies: function () {
        return ["StandardPersistence", "CreditManager"];
    }
}
