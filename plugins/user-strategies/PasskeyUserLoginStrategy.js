const UserLoginStrategyInterface = require('./UserLoginStrategyInterface');
const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../../constants/authConstants');
const AUDIT_EVENTS = require('../../Persisto/src/audit/AuditEvents.cjs');
const SystemAudit = require('../../Persisto/src/audit/SystemAudit.cjs');
const fs = require('fs');
const path = require('path');
const ROOTS_PEM_PATH = path.join(__dirname, '../../roots.pem');
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
                authMetadata: {
                    publicKeyCredentialRequestOptions: JSON.stringify(publicKeyCredentialRequestOptions),
                    challengeKey: challengeKey
                }
            };
        } else {
            // No passkeys registered for this user, so Passkey strategy cannot be active here for login.
            // It might still be an authType if user *could* register one.
            return {
                authTypes: user.authTypes,
                activeAuthType: user.authTypes.includes(AUTH_TYPES.EMAIL) ? AUTH_TYPES.EMAIL : user.authTypes[0],
                authMetadata: {}
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

        if (!this.parsedTrustedRoots) {
            const rootsPem = fs.readFileSync(ROOTS_PEM_PATH, 'utf8');
            this.parsedTrustedRoots = this.webauthnUtils.parseRootsPem(rootsPem);
        }

        try {
            const credentialInfo = await this.webauthnUtils.verifyRegistrationResponse(
                registrationData,
                undefined,
                process.env.ORIGIN,
                process.env.RP_ID,
                true,
                this.parsedTrustedRoots
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
                    userId: userPayload.globalUserId,
                    publicKey: publicKey,
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

            if (!this.parsedTrustedRoots) {
                const rootsPem = fs.readFileSync(ROOTS_PEM_PATH, 'utf8');
                this.parsedTrustedRoots = this.webauthnUtils.parseRootsPem(rootsPem);
            }

            const verificationResult = await this.webauthnUtils.verifyAssertionResponse(
                assertion,
                credentialForVerification,
                challenge,
                process.env.ORIGIN,
                process.env.RP_ID,
                true,
                this.parsedTrustedRoots
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

    async handleGetEmailCode(user) {
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
            const systemAudit = SystemAudit.getSystemAudit();
            await systemAudit.smartLog(AUDIT_EVENTS.PASSKEY_REGISTER, {
                userId: user.globalUserId,
                publicKey: newCredential.publicKey.toString('base64url'),
            });
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

    async handleDeletePasskey(user, credentialId) {
        if (!user.passkeyCredentials || user.passkeyCredentials.length === 0) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.NO_PASSKEYS_REGISTERED
            };
        }

        const passKeyIndex = user.passkeyCredentials.findIndex(cred => cred.id === credentialId);

        if (passKeyIndex === -1) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.PASSKEY_NOT_FOUND
            };
        }

        const hasOtherAuthMethods = user.authTypes && user.authTypes.length > 1;
        const isLastPasskey = user.passkeyCredentials.length === 1;

        if (isLastPasskey && !hasOtherAuthMethods) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.CANNOT_DELETE_LAST_AUTH_METHOD
            };
        }

        const passkey = user.passkeyCredentials[passKeyIndex];
        const passkeyName = passkey.name || 'Unknown';

        user.passkeyCredentials.splice(passKeyIndex, 1);

        if (user.passkeyCredentials.length === 0 && user.authTypes) {
            const passKeyAuthIndex = user.authTypes.indexOf(AUTH_TYPES.PASSKEY);
            if (passKeyAuthIndex !== -1) {
                user.authTypes.splice(passKeyAuthIndex, 1);
            }
        }

        await this.persistence.updateUserLoginStatus(user.id, user);

        try {
            const systemAudit = SystemAudit.getSystemAudit();
            await systemAudit.smartLog(AUDIT_EVENTS.PASSKEY_DELETE, {
                userId: user.globalUserId,
                publicKey: passkey.publicKey.toString('base64url'),
            });
        } catch (auditError) {
            console.error("Failed to log passkey deletion to audit:", auditError);
        }

        console.log(`Deleted passkey "${passkeyName}" for user ${user.email}`);

        return {
            status: STATUS.SUCCESS,
            message: `Passkey "${passkeyName}" was successfully deleted`
        };
    }
}

module.exports = PasskeyUserLoginStrategy; 