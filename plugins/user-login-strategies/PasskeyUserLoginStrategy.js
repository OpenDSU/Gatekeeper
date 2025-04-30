const UserLoginStrategyInterface = require('./UserLoginStrategyInterface');
const process = require("process");
const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../../constants/authConstants');
class PasskeyUserLoginStrategy extends UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        super(persistence, webauthnUtils, crypto, loginChallenges);
    }

    async handleUserExists(user) {
        if (!user.authTypes) {
            user.authTypes = user.authType ? [user.authType] : [AUTH_TYPES.EMAIL];
        }

        if (user.passkeyCredentials && user.passkeyCredentials.length > 0) {
            const allowCredentials = user.passkeyCredentials.map(cred => ({
                type: 'public-key',
                id: cred.id,
                transports: cred.transports
            }));

            const challenge = this.crypto.randomBytes(32).toString("base64url");
            const challengeKey = `login_challenge_${user.email}_${Date.now()}`;
            this.loginChallenges.set(challengeKey, challenge);
            setTimeout(() => this.loginChallenges.delete(challengeKey), 5 * 60 * 1000);

            const publicKeyCredentialRequestOptions = {
                challenge: challenge,
                allowCredentials: allowCredentials,
                rpId: process.env.RP_ID,
                userVerification: 'required',
                timeout: 60000,
            };

            return {
                authTypes: user.authTypes,
                activeAuthType: AUTH_TYPES.PASSKEY,
                publicKeyCredentialRequestOptions: JSON.stringify(publicKeyCredentialRequestOptions),
                challengeKey: challengeKey
            };
        } else {
            return {
                authTypes: user.authTypes,
                activeAuthType: user.authTypes[0]
            };
        }
    }

    async handleCreateUser(userPayload, registrationData) {
        if (!registrationData) {
            throw new Error("Missing registration data for passkey user creation.");
        }

        if (!userPayload.authTypes) {
            userPayload.authTypes = [AUTH_TYPES.PASSKEY];
        } else if (!userPayload.authTypes.includes(AUTH_TYPES.PASSKEY)) {
            userPayload.authTypes.push(AUTH_TYPES.PASSKEY);
        }

        try {
            const credentialInfo = await this.webauthnUtils.verifyRegistrationResponse(
                registrationData,
                undefined,
                process.env.ORIGIN,
                process.env.RP_ID,
                true
            );

            userPayload.passkeyCredentials = [{
                id: credentialInfo.credentialId.toString('base64url'),
                publicKey: credentialInfo.credentialPublicKey.toString('base64url'),
                signCount: credentialInfo.signCount,
                aaguid: credentialInfo.aaguid.toString('base64url'),
                fmt: credentialInfo.attestationFormat,
                transports: registrationData.response.transports || [],
                name: "Primary Passkey",
                createdAt: new Date().toISOString()
            }];

        } catch (e) {
            console.error("Passkey registration verification failed during user creation:", e);
            throw new Error(`Passkey registration verification failed: ${e.message}`);
        }
    }

    async handleAuthorizeUser(user, loginData, challengeKey) {
        const assertion = loginData;

        if (!user.authTypes) {
            user.authTypes = user.authType ? [user.authType] : [AUTH_TYPES.EMAIL];
        }

        if (!assertion || typeof assertion !== 'object' || !assertion.id || !challengeKey) {
            return { verified: false, reason: ERROR_REASONS.INVALID_PASSKEY_LOGIN_DATA };
        }

        const challenge = this.loginChallenges.get(challengeKey);
        if (!challenge) {
            return { verified: false, reason: ERROR_REASONS.LOGIN_CHALLENGE_EXPIRED };
        }
        this.loginChallenges.delete(challengeKey);

        const credentialIdB64 = assertion.id;
        const storedCredential = user.passkeyCredentials.find(cred => cred.id === credentialIdB64);

        if (!storedCredential) {
            return { verified: false, reason: ERROR_REASONS.PASSKEY_NOT_REGISTERED };
        }

        try {
            const credentialForVerification = {
                id: storedCredential.id,
                publicKey: storedCredential.publicKey,
                signCount: storedCredential.signCount
            };

            const verificationResult = await this.webauthnUtils.verifyAssertionResponse(
                assertion,
                credentialForVerification,
                challenge,
                process.env.ORIGIN,
                process.env.RP_ID,
                true
            );

            const updatedSignCount = verificationResult.newSignCount;

            const update = {
                passkeyCredentials: user.passkeyCredentials.map(cred =>
                    cred.id === storedCredential.id
                        ? { ...cred, signCount: updatedSignCount }
                        : cred
                )
            };

            return { verified: true, update: update };

        } catch (e) {
            console.error("Passkey assertion verification failed:", e);
            return { verified: false, reason: `Invalid passkey assertion: ${e.message}` };
        }
    }

    async handleGetUserValidationCode(user) {
        return {
            status: STATUS.FAILED,
            reason: ERROR_REASONS.ACCOUNT_USES_PASSKEY,
            authTypes: user.authTypes || [AUTH_TYPES.PASSKEY]
        };
    }

    async handleRegisterNewPasskey(user, registrationData) {
        try {
            if (!user.authTypes) {
                user.authTypes = user.authType ? [user.authType] : [AUTH_TYPES.EMAIL];
            }

            if (!user.authTypes.includes(AUTH_TYPES.PASSKEY)) {
                user.authTypes.push(AUTH_TYPES.PASSKEY);
            }

            const credentialInfo = await this.webauthnUtils.verifyRegistrationResponse(
                registrationData,
                undefined,
                process.env.ORIGIN,
                process.env.RP_ID,
                true
            );

            if (!user.passkeyCredentials) {
                user.passkeyCredentials = [];
            }
            const credentialIdB64 = credentialInfo.credentialId.toString('base64url');
            const existingCredential = user.passkeyCredentials.find(cred => cred.id === credentialIdB64);
            if (existingCredential) {
                throw new Error("This passkey is already registered for this account.");
            }

            const newCredential = {
                id: credentialIdB64,
                publicKey: credentialInfo.credentialPublicKey.toString('base64url'),
                signCount: credentialInfo.signCount,
                aaguid: credentialInfo.aaguid.toString('base64url'),
                fmt: credentialInfo.attestationFormat,
                transports: registrationData.response.transports || [],
                name: `Passkey added ${new Date().toLocaleDateString()}`,
                createdAt: new Date().toISOString()
            };

            user.passkeyCredentials.push(newCredential);

            await this.persistence.updateUserLoginStatus(user.id, user);
            return { status: STATUS.SUCCESS, credentialId: credentialIdB64 };

        } catch (e) {
            console.error("Failed to register new passkey:", e);
            throw new Error(`Failed to register new passkey: ${e.message}`);
        }
    }
}

module.exports = PasskeyUserLoginStrategy; 