const { generateId, generateWalletKey, getLoginStrategy } = require('../utils/pluginUtils');
const expiryTimeout = 5 * 60 * 1000;
const maxLoginAttempts = 5;

const sessionCache = new Map();

// Temporary cache for validation codes for non-existent users
const tempCodeCache = new Map();

// Cache for tracking registration attempts by email to prevent spam
// This includes: email code generation for new users, user creation, 
// passkey registration, and TOTP setup attempts
const registrationAttemptCache = new Map();

const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../constants/authConstants');
const otpauth = require('../authenticator/totp/otpauth/index.cjs');

async function UserLogin() {
    let self = {};
    let persistence = await $$.loadPlugin("StandardPersistence");
    let CreditManager = await $$.loadPlugin("CreditManager");

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
            const strategy = getLoginStrategy(defaultAuthType, persistence);
            const strategyResult = await strategy.userExists(user);

            let finalAuthMetadata = { ...(strategyResult.authMetadata || {}) };
            finalAuthMetadata.totpEnabled = !!user.totpEnabled;
            finalAuthMetadata.totpPendingSetup = !!user.totpPendingSetup;

            // Get passkey challenge if user has passkeys
            if (user.passkeyCredentials && user.passkeyCredentials.length > 0 && defaultAuthType !== AUTH_TYPES.PASSKEY) {
                const passkeyStrategy = getLoginStrategy(AUTH_TYPES.PASSKEY, persistence);
                const passkeyStrategyResult = await passkeyStrategy.userExists(user);
                if (passkeyStrategyResult.authMetadata) {
                    if (passkeyStrategyResult.authMetadata.publicKeyCredentialRequestOptions) {
                        finalAuthMetadata.publicKeyCredentialRequestOptions = passkeyStrategyResult.authMetadata.publicKeyCredentialRequestOptions;
                    }
                    if (passkeyStrategyResult.authMetadata.challengeKey) {
                        finalAuthMetadata.challengeKey = passkeyStrategyResult.authMetadata.challengeKey;
                    }
                }
            }

            if (strategyResult.authMetadata?.publicKeyCredentialRequestOptions) {
                finalAuthMetadata.publicKeyCredentialRequestOptions = strategyResult.authMetadata.publicKeyCredentialRequestOptions;
            }
            if (strategyResult.authMetadata?.challengeKey) {
                finalAuthMetadata.challengeKey = strategyResult.authMetadata.challengeKey;
            }

            return {
                status: STATUS.SUCCESS,
                userExists: true,
                authTypes: user.authTypes || [AUTH_TYPES.EMAIL],
                activeAuthType: strategyResult.activeAuthType || defaultAuthType,
                authMetadata: finalAuthMetadata
            };
        }
        return {
            status: STATUS.SUCCESS,
            userExists: false,
            authTypes: [AUTH_TYPES.EMAIL],
            activeAuthType: AUTH_TYPES.EMAIL,
            authMetadata: {}
        };
    }

    self.createUser = async function (email, name, referrerId) {
        // Check registration attempt rate limiting
        const registrationCheck = checkRegistrationAttempts(email);
        if (!registrationCheck.allowed) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                lockTime: registrationCheck.lockTime
            };
        }

        let walletKey = generateWalletKey();
        name = name || email.split("@")[0];
        let userAsset = await CreditManager.addUser(email, name, referrerId);

        // Users can ONLY register with email - other auth types can be added later
        const defaultAuthType = AUTH_TYPES.EMAIL;
        const strategy = getLoginStrategy(defaultAuthType, persistence);

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

        await strategy.createUser(userPayload, null);

        let user = await persistence.createUserLoginStatus(userPayload);
        let sessionId = await createSessionForUser(user);
        user.sessionId = sessionId;
        user.status = STATUS.SUCCESS;
        user.globalUserId = userAsset.id;

        // Track this registration attempt
        incrementRegistrationAttempts(email);

        return user;
    }

    // Dedicated login method for email code
    self.loginWithEmailCode = async function (email, code) {
        let userExists = await persistence.hasUserLoginStatus(email);

        if (!userExists) {
            // Check registration attempt rate limiting for validation attempts
            const registrationCheck = checkRegistrationAttempts(email);
            if (!registrationCheck.allowed) {
                return {
                    status: STATUS.FAILED,
                    reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                    lockTime: registrationCheck.lockTime
                };
            }

            // Check if there's a temporary code for this email
            const tempData = tempCodeCache.get(email);
            if (!tempData) {
                // Track failed validation attempt
                incrementRegistrationAttempts(email);
                return { status: STATUS.FAILED, reason: ERROR_REASONS.ACCOUNT_NOT_EXISTS };
            }

            // Validate the temporary code
            let now = new Date().getTime();
            if (tempData.code === code) {
                if (now - new Date(tempData.timestamp).getTime() > expiryTimeout) {
                    tempCodeCache.delete(email);
                    // Track failed validation attempt (expired code)
                    incrementRegistrationAttempts(email);
                    return { status: STATUS.FAILED, reason: ERROR_REASONS.CODE_EXPIRED };
                }

                // Code is valid, create the user now
                try {
                    tempCodeCache.delete(email);
                    let user = await self.createUser(email, tempData.name, tempData.referrerId);

                    return {
                        status: STATUS.SUCCESS,
                        sessionId: user.sessionId,
                        email: email,
                        walletKey: user.walletKey,
                        userInfo: user.userInfo,
                        userId: user.globalUserId
                    };
                } catch (e) {
                    console.error(`Error creating user after email validation:`, e);
                    return { status: STATUS.FAILED, reason: `User creation error: ${e.message}` };
                }
            } else {
                // Track failed validation attempt (wrong code)
                incrementRegistrationAttempts(email);
                return { status: STATUS.FAILED, reason: ERROR_REASONS.INVALID_CODE };
            }
        }

        // User exists - handle normally with login attempts tracking
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
                user = await resetLoginAttempts(email);
            }
        }

        const strategy = getLoginStrategy(AUTH_TYPES.EMAIL, persistence);
        let verificationResult;

        try {
            verificationResult = await strategy.verifyCredentials(user, code);
        } catch (e) {
            console.error(`Error during email code authorization:`, e);
            await incrementLoginAttempts(user.email);
            return { status: STATUS.FAILED, reason: `Authorization error: ${e.message}` };
        }

        if (verificationResult.verified) {
            user = await resetLoginAttempts(user.email);

            if (verificationResult.update && typeof verificationResult.update === 'object') {
                Object.assign(user, verificationResult.update);
                await persistence.updateUserLoginStatus(user.id, user);
            }
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
            await incrementLoginAttempts(user.email);
            return { status: STATUS.FAILED, reason: verificationResult.reason || ERROR_REASONS.INVALID_CREDENTIALS };
        }
    }

    // Dedicated login method for passkey
    self.loginWithPasskey = async function (email, assertion, challengeKey) {
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
                user = await resetLoginAttempts(email);
            }
        }

        const strategy = getLoginStrategy(AUTH_TYPES.PASSKEY, persistence);
        let verificationResult;

        try {
            verificationResult = await strategy.verifyCredentials(user, assertion, challengeKey);
        } catch (e) {
            console.error(`Error during passkey authorization:`, e);
            await incrementLoginAttempts(user.email);
            return { status: STATUS.FAILED, reason: `Authorization error: ${e.message}` };
        }

        if (verificationResult.verified) {
            user = await resetLoginAttempts(user.email);

            if (verificationResult.update && typeof verificationResult.update === 'object') {
                Object.assign(user, verificationResult.update);
                await persistence.updateUserLoginStatus(user.id, user);
            }
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
            await incrementLoginAttempts(user.email);
            return { status: STATUS.FAILED, reason: verificationResult.reason || ERROR_REASONS.INVALID_CREDENTIALS };
        }
    }

    // Dedicated login method for TOTP
    self.loginWithTotp = async function (email, token) {
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
                user = await resetLoginAttempts(email);
            }
        }

        const strategy = getLoginStrategy(AUTH_TYPES.TOTP, persistence);
        let verificationResult;

        try {
            verificationResult = await strategy.verifyCredentials(user, token);
        } catch (e) {
            console.error(`Error during TOTP authorization:`, e);
            await incrementLoginAttempts(user.email);
            return { status: STATUS.FAILED, reason: `Authorization error: ${e.message}` };
        }

        if (verificationResult.verified) {
            user = await resetLoginAttempts(user.email);

            if (verificationResult.update && typeof verificationResult.update === 'object') {
                Object.assign(user, verificationResult.update);
                await persistence.updateUserLoginStatus(user.id, user);
            }
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
            await incrementLoginAttempts(user.email);
            return { status: STATUS.FAILED, reason: verificationResult.reason || ERROR_REASONS.INVALID_CREDENTIALS };
        }
    }

    self.addPasskey = async function (email, registrationData) {
        let user = await persistence.getUserLoginStatus(email);
        if (!user) {
            throw new Error(ERROR_REASONS.USER_NOT_EXISTS);
        }

        // Check registration attempt rate limiting for additional passkeys
        const registrationCheck = checkRegistrationAttempts(email);
        if (!registrationCheck.allowed) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                lockTime: registrationCheck.lockTime
            };
        }

        const strategy = getLoginStrategy(AUTH_TYPES.PASSKEY, persistence);
        if (!strategy || typeof strategy.addPasskey !== 'function') {
            throw new Error("Passkey strategy not available or invalid.");
        }

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (!user.authTypes.includes(AUTH_TYPES.EMAIL)) {
            user.authTypes.push(AUTH_TYPES.EMAIL);
        }

        try {
            const result = await strategy.addPasskey(user, registrationData);

            if (!user.authTypes.includes(AUTH_TYPES.PASSKEY)) {
                user.authTypes.push(AUTH_TYPES.PASSKEY);
                await persistence.updateUserLoginStatus(user.id, user);
            }

            // Track this registration attempt only if successful
            if (result.status === STATUS.SUCCESS) {
                incrementRegistrationAttempts(email);
            }

            return result;
        } catch (e) {
            console.error("Error during addPasskey handling:", e);
            // Track failed registration attempt
            incrementRegistrationAttempts(email);
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

        return sessionId;
    }

    self.requestEmailCode = async function (email, name, referrerId) {
        let userExists = await persistence.hasUserLoginStatus(email);
        let user;

        if (!userExists) {
            // Check registration attempt rate limiting for non-existing users
            const registrationCheck = checkRegistrationAttempts(email);
            if (!registrationCheck.allowed) {
                return {
                    status: STATUS.FAILED,
                    reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                    lockTime: registrationCheck.lockTime
                };
            }

            // Generate a validation code and store it temporarily without creating the user
            const emailStrategy = getLoginStrategy(AUTH_TYPES.EMAIL, persistence);
            const code = emailStrategy.generateValidationCode(5);

            const timestamp = new Date().toISOString();
            const tempData = {
                code: code,
                timestamp: timestamp,
                name: name,
                referrerId: referrerId
            };

            // Store in temporary cache with expiry
            tempCodeCache.set(email, tempData);
            setTimeout(() => tempCodeCache.delete(email), expiryTimeout);

            // Track this registration attempt
            incrementRegistrationAttempts(email);

            return {
                status: STATUS.SUCCESS,
                code: code,
                authTypes: [AUTH_TYPES.EMAIL]
            };
        }

        user = await persistence.getUserLoginStatus(email);

        let now = new Date().getTime();
        if (user.loginAttempts >= maxLoginAttempts) {
            if (user.lastLoginAttempt && now < user.lastLoginAttempt + expiryTimeout) {
                return {
                    status: STATUS.FAILED,
                    reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                    lockTime: user.lastLoginAttempt + expiryTimeout - now
                };
            }
            user = await resetLoginAttempts(email);
        }

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const strategy = getLoginStrategy(AUTH_TYPES.EMAIL, persistence);

        return await strategy.getEmailCode(user);
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

        const strategy = getLoginStrategy(AUTH_TYPES.PASSKEY, persistence);
        if (!strategy || typeof strategy.deletePasskey !== 'function') {
            throw new Error("Passkey strategy not available or invalid.");
        }

        try {
            return await strategy.deletePasskey(user, credentialId);
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

        const strategy = getLoginStrategy(AUTH_TYPES.TOTP, persistence);
        if (!strategy || typeof strategy.deleteTotp !== 'function') {
            throw new Error("TOTP strategy not available or invalid.");
        }

        try {
            return await strategy.deleteTotp(user);
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

    const incrementLoginAttempts = async function (email) {
        try {
            let user = await persistence.getUserLoginStatus(email);
            if (!user) return;
            user.loginAttempts = (user.loginAttempts || 0) + 1;
            user.lastLoginAttempt = new Date().getTime();
            await persistence.updateUserLoginStatus(user.id, user);
        } catch (e) {
            console.error(`Failed to increment login attempts for ${email}:`, e);
        }
    }

    const resetLoginAttempts = async function (email) {
        try {
            let user = await persistence.getUserLoginStatus(email);
            if (!user) return null;
            user.loginAttempts = 0;
            user.lastLoginAttempt = null;
            await persistence.updateUserLoginStatus(user.id, user);
            return user;
        } catch (e) {
            console.error(`Failed to reset login attempts for ${email}:`, e);
            return null;
        }
    }

    const incrementRegistrationAttempts = function (email) {
        // Track registration attempts by email to prevent spam registrations
        // This is used for: email code generation for new users, user creation,
        // passkey registration, and TOTP setup attempts
        const now = new Date().getTime();
        const attempts = registrationAttemptCache.get(email) || { count: 0, lastAttempt: null };

        // Reset if outside timeout window
        if (attempts.lastAttempt && now - attempts.lastAttempt > expiryTimeout) {
            attempts.count = 0;
        }

        attempts.count += 1;
        attempts.lastAttempt = now;
        registrationAttemptCache.set(email, attempts);

        // Clean up old entries
        setTimeout(() => {
            const currentAttempts = registrationAttemptCache.get(email);
            if (currentAttempts && now - currentAttempts.lastAttempt > expiryTimeout) {
                registrationAttemptCache.delete(email);
            }
        }, expiryTimeout);
    }

    const checkRegistrationAttempts = function (email) {
        // Check if email has exceeded registration attempt limits
        // Returns {allowed: boolean, lockTime: number}
        const now = new Date().getTime();
        const attempts = registrationAttemptCache.get(email);

        if (!attempts) {
            return { allowed: true, lockTime: 0 };
        }

        // Reset if outside timeout window
        if (attempts.lastAttempt && now - attempts.lastAttempt > expiryTimeout) {
            registrationAttemptCache.delete(email);
            return { allowed: true, lockTime: 0 };
        }

        if (attempts.count >= maxLoginAttempts) {
            const lockTime = attempts.lastAttempt + expiryTimeout - now;
            return { allowed: false, lockTime: lockTime };
        }

        return { allowed: true, lockTime: 0 };
    }

    self.shutDown = async function () {
        await persistence.shutDown();
        return { status: STATUS.SUCCESS };
    }

    self.setupTotp = async function (email) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }

        let user = await persistence.getUserLoginStatus(email);

        // Check registration attempt rate limiting for TOTP setup
        const registrationCheck = checkRegistrationAttempts(email);
        if (!registrationCheck.allowed) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                lockTime: registrationCheck.lockTime
            };
        }

        // Generate a new TOTP secret
        const secret = new otpauth.Secret();
        const totp = new otpauth.TOTP({
            issuer: process.env.APP_NAME || 'MyApp',
            label: email,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: secret
        });

        const uri = totp.toString();

        // Store the secret using the strategy
        const strategy = getLoginStrategy(AUTH_TYPES.TOTP, persistence);
        if (!strategy || typeof strategy.setTotpSecret !== 'function') {
            throw new Error("TOTP strategy not available or invalid.");
        }

        try {
            await strategy.setTotpSecret(user, secret.base32);

            // Track this registration attempt
            incrementRegistrationAttempts(email);

            return {
                status: STATUS.SUCCESS,
                uri: uri,
                secret: secret.base32
            };
        } catch (e) {
            console.error(`Error setting TOTP secret for ${email}:`, e);
            // Track failed registration attempt
            incrementRegistrationAttempts(email);
            return { status: STATUS.FAILED, reason: `Failed to set TOTP secret: ${e.message}` };
        }
    }

    self.confirmTotpSetup = async function (email, token) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: STATUS.FAILED, reason: ERROR_REASONS.USER_NOT_EXISTS };
        }
        let user = await persistence.getUserLoginStatus(email);

        // Check login attempts for TOTP verification to prevent brute force
        let now = new Date().getTime();
        if (user.loginAttempts >= maxLoginAttempts) {
            if (user.lastLoginAttempt && now < user.lastLoginAttempt + expiryTimeout) {
                return {
                    status: STATUS.FAILED,
                    reason: ERROR_REASONS.EXCEEDED_ATTEMPTS,
                    lockTime: user.lastLoginAttempt + expiryTimeout - now
                };
            } else {
                user = await resetLoginAttempts(email);
            }
        }

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (!user.authTypes.includes(AUTH_TYPES.EMAIL)) {
            user.authTypes.push(AUTH_TYPES.EMAIL);
        }

        const strategy = getLoginStrategy(AUTH_TYPES.TOTP, persistence);
        if (!strategy || typeof strategy.confirmTotpSetup !== 'function') {
            throw new Error("TOTP strategy not available or invalid.");
        }

        try {
            const result = await strategy.confirmTotpSetup(user, token);
            if (result.verified) {
                // Reset login attempts on successful verification
                user = await resetLoginAttempts(email);

                if (!user.authTypes.includes(AUTH_TYPES.TOTP)) {
                    user.authTypes.push(AUTH_TYPES.TOTP);
                    await persistence.updateUserLoginStatus(user.id, user);
                }
                return { status: STATUS.SUCCESS };
            } else {
                // Increment login attempts on failed verification
                await incrementLoginAttempts(email);
                return { status: STATUS.FAILED, reason: result.reason || ERROR_REASONS.INVALID_TOTP_CODE };
            }
        } catch (e) {
            console.error(`Error verifying/enabling TOTP for ${email}:`, e);
            // Increment login attempts on error
            await incrementLoginAttempts(email);
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
            let userExists;
            switch (command) {
                case "createUser":
                    userExists = await singletonInstance.persistence.hasUserLoginStatus(args[0]);
                    if (userExists) {
                        return false;
                    }
                    return true;
                case "userExists":
                case "checkSessionId":
                case "loginWithEmailCode":
                case "loginWithPasskey":
                case "loginWithTotp":
                case "logout":
                    return true;
                case "getUserInfo":
                    if (globalUserId === "*") {
                        return true;
                    }
                    user = await singletonInstance.persistence.getUserLoginStatus(args[0]);
                    if (user.globalUserId === globalUserId) {
                        return true;
                    }
                    return false;

                case "deletePasskey":
                case "deleteTotp":
                case "setUserInfo":
                case "addPasskey":
                case "confirmTotpSetup":
                case "setupTotp":
                    user = await singletonInstance.persistence.getUserLoginStatus(args[0]);
                    if (user && user.globalUserId === globalUserId) {
                        return true;
                    }
                    return false;
                case "requestEmailCode":
                    userExists = await singletonInstance.persistence.hasUserLoginStatus(args[0]);
                    if (!userExists) {
                        return true;
                    }
                    user = await singletonInstance.persistence.getUserLoginStatus(args[0]);
                    if (user && user.globalUserId === globalUserId) {
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