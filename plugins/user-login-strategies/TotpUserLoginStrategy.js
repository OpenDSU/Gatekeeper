const UserLoginStrategyInterface = require('./UserLoginStrategyInterface');
const { AUTH_TYPES, STATUS, ERROR_REASONS, TOTP_SETTINGS } = require('../../constants/authConstants');

class TotpUserLoginStrategy extends UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        super(persistence, webauthnUtils, crypto, loginChallenges);
    }

    async handleUserExists(user) {
        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        const hasTotpAuth = user.authTypes.includes(AUTH_TYPES.TOTP);

        if (user.totpSecret && user.totpEnabled) {
            return {
                authTypes: user.authTypes,
                activeAuthType: AUTH_TYPES.TOTP
            };
        } else if (user.totpSecret && !user.totpEnabled) {
            return {
                authTypes: user.authTypes,
                activeAuthType: hasTotpAuth ? AUTH_TYPES.TOTP : user.authTypes[0],
                setupPending: true
            };
        } else {
            return {
                authTypes: user.authTypes,
                activeAuthType: user.authTypes[0],
                error: ERROR_REASONS.INCOMPLETE_TOTP_SETUP
            };
        }
    }

    async handleCreateUser(userPayload, _registrationData) {
        userPayload.totpSecret = undefined;
        userPayload.totpEnabled = false;
        userPayload.totpPendingSetup = true;

        if (!userPayload.authTypes) {
            userPayload.authTypes = [AUTH_TYPES.TOTP];
        } else if (!userPayload.authTypes.includes(AUTH_TYPES.TOTP)) {
            userPayload.authTypes.push(AUTH_TYPES.TOTP);
        }
    }

    async handleAuthorizeUser(user, loginData, _challengeKey) {
        const totpCode = loginData;

        if (typeof totpCode !== 'string') {
            return { verified: false, reason: ERROR_REASONS.INVALID_TOTP_FORMAT };
        }

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (!user.totpSecret || !user.totpEnabled) {
            return { verified: false, reason: ERROR_REASONS.TOTP_NOT_ENABLED };
        }

        try {
            const totp = new this.otpauth.TOTP({
                issuer: TOTP_SETTINGS.ISSUER,
                label: user.email,
                algorithm: TOTP_SETTINGS.ALGORITHM,
                digits: TOTP_SETTINGS.DIGITS,
                period: TOTP_SETTINGS.PERIOD,
                secret: user.totpSecret // Use the stored secret directly (should be base32)
            });

            const delta = totp.validate({ token: totpCode, window: 1 });

            if (delta !== null) {
                return { verified: true };
            } else {
                return { verified: false, reason: ERROR_REASONS.INVALID_TOTP_CODE };
            }
        } catch (e) {
            console.error("TOTP validation error:", e);
            return { verified: false, reason: `TOTP validation error: ${e.message}` };
        }
    }

    async handleGetUserValidationCode(_user) {
        return {
            status: STATUS.FAILED,
            reason: ERROR_REASONS.USE_TOTP,
            authTypes: _user.authTypes || [AUTH_TYPES.TOTP]
        };
    }

    async handleSetTotpSecret(user, secret) {
        user.totpSecret = secret;
        user.totpEnabled = false;
        user.totpPendingSetup = true;

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (!user.authTypes.includes(AUTH_TYPES.TOTP)) {
            user.authTypes.push(AUTH_TYPES.TOTP);
        }

        await this.persistence.updateUserLoginStatus(user.id, user);
    }

    async handleVerifyAndEnableTotp(user, token) {
        if (!user.totpSecret) {
            return { verified: false, reason: ERROR_REASONS.TOTP_SETUP_NOT_INITIATED };
        }

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        try {
            const totp = new this.otpauth.TOTP({
                issuer: TOTP_SETTINGS.ISSUER,
                label: user.email,
                algorithm: TOTP_SETTINGS.ALGORITHM,
                digits: TOTP_SETTINGS.DIGITS,
                period: TOTP_SETTINGS.PERIOD,
                secret: user.totpSecret
            });

            const delta = totp.validate({ token: token, window: 1 });

            if (delta !== null) {
                user.totpEnabled = true;
                user.totpPendingSetup = false;

                if (!user.authTypes.includes(AUTH_TYPES.TOTP)) {
                    user.authTypes.push(AUTH_TYPES.TOTP);
                }

                user.validationEmailCode = undefined;
                user.validationEmailCodeTimestamp = undefined;

                await this.persistence.updateUserLoginStatus(user.id, user);
                return { verified: true };
            } else {
                return { verified: false, reason: ERROR_REASONS.INVALID_TOTP_CODE };
            }
        } catch (error) {
            console.error("TOTP verification error during enable:", error);
            return { verified: false, reason: `Verification error: ${error.message}` };
        }
    }
}

module.exports = TotpUserLoginStrategy; 