const UserLoginStrategyInterface = require('./UserLoginStrategyInterface');
const process = require("process");
const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../../constants/authConstants');
const AUDIT_EVENTS = require('../../Persisto/src/audit/AuditEvents.cjs');
const SystemAudit = require('../../Persisto/src/audit/SystemAudit.cjs');
const fs = require('fs');
const path = require('path');

// Load authenticator name map
const authenticatorNameMap = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../../authenticator/webauthn/authenticatorNameMap.json'), 'utf8')
);

class PasskeyUserLoginStrategy extends UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        super(persistence, webauthnUtils, crypto, loginChallenges);
    }

    /**
     * Get the human-readable authenticator name from an AAGUID
     * @param {Buffer|string} aaguid - The AAGUID as Buffer or hex string
     * @returns {string} The authenticator name or a fallback name
     */
    getAuthenticatorName(aaguid) {

        const aaguidHex = Buffer.isBuffer(aaguid) ? aaguid.toString('hex') : aaguid;
        const aaguidFormatted = [
            aaguidHex.slice(0, 8),
            aaguidHex.slice(8, 12),
            aaguidHex.slice(12, 16),
            aaguidHex.slice(16, 20),
            aaguidHex.slice(20, 32)
        ].join('-');
        return authenticatorNameMap[aaguidFormatted] || 'Unknown Authenticator';
    }

    async handleUserExists(user) {
        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
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

            const credentialId = credentialInfo.credentialId.toString('base64url');
            const publicKey = credentialInfo.credentialPublicKey.toString('base64url');

            // Get the AAGUID and get authenticator name
            const aaguidHex = credentialInfo.aaguid.toString('hex');
            const authenticatorName = this.getAuthenticatorName(aaguidHex);

            const transports = registrationData.response.transports || [];

            userPayload.passkeyCredentials = [{
                id: credentialId,
                publicKey: publicKey,
                signCount: credentialInfo.signCount,
                aaguid: aaguidHex,
                fmt: credentialInfo.attestationFormat,
                transports: transports,
                name: authenticatorName,
                createdAt: new Date().toISOString()
            }];

            try {
                const systemAudit = SystemAudit.getSystemAudit();
                await systemAudit.smartLog(AUDIT_EVENTS.PASSKEY_REGISTER, {
                    email: userPayload.email,
                    credentialId: credentialId,
                    publicKey: publicKey,
                    aaguid: aaguidHex,
                    transports: transports,
                    createdAt: new Date().toISOString()
                });
            } catch (auditError) {
                console.error("Failed to log initial passkey registration to audit:", auditError);
            }

        } catch (e) {
            console.error("Passkey registration verification failed during user creation:", e);
            throw new Error(`Passkey registration verification failed: ${e.message}`);
        }
    }

    async handleAuthorizeUser(user, loginData, challengeKey) {
        const assertion = loginData;

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
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
        if (!registrationData) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.INVALID_REGISTRATION_DATA
            };
        }

        try {
            const verificationResult = await this.webauthnUtils.verifyRegistrationResponse(
                registrationData,
                undefined,
                process.env.ORIGIN,
                process.env.RP_ID,
                true
            );

            const aaguidHex = verificationResult.aaguid.toString('hex');
            const authenticatorName = this.getAuthenticatorName(aaguidHex);

            if (!user.passkeyCredentials) {
                user.passkeyCredentials = [];
            }

            const existingCredential = user.passkeyCredentials.find(
                cred => cred.id === verificationResult.credentialId.toString('base64url')
            );

            if (existingCredential) {
                return {
                    status: STATUS.FAILED,
                    reason: ERROR_REASONS.CREDENTIAL_ALREADY_EXISTS
                };
            }

            const newCredential = {
                id: verificationResult.credentialId.toString('base64url'),
                publicKey: verificationResult.credentialPublicKey,
                signCount: verificationResult.signCount,
                aaguid: aaguidHex,
                name: authenticatorName,
                transports: registrationData.response.transports || [],
                createdAt: new Date().toISOString()
            };

            user.passkeyCredentials.push(newCredential);
            await this.persistence.updateUserLoginStatus(user.id, user);

            console.log(`Added new passkey for user ${user.email} with authenticator: ${authenticatorName}`);

            return {
                status: STATUS.SUCCESS,
                credentialId: newCredential.id,
                name: authenticatorName
            };
        } catch (e) {
            console.error("Error during passkey registration:", e);
            return {
                status: STATUS.FAILED,
                reason: `Passkey registration failed: ${e.message}`
            };
        }
    }
}

module.exports = PasskeyUserLoginStrategy; 