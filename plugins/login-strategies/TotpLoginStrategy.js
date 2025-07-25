const UserLoginStrategyInterface = require('./LoginStrategyInterface');
const { AUTH_TYPES, STATUS, ERROR_REASONS, TOTP_SETTINGS } = require('../../constants/authConstants');

class TotpUserLoginStrategy extends UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        super(persistence, webauthnUtils, crypto, loginChallenges);
    }

    async userExists(user) {
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

    async createUser(userPayload) {
        userPayload.totpSecret = undefined;
        userPayload.totpEnabled = false;
        userPayload.totpPendingSetup = true;

        if (!userPayload.authTypes) {
            userPayload.authTypes = [AUTH_TYPES.TOTP];
        } else if (!userPayload.authTypes.includes(AUTH_TYPES.TOTP)) {
            userPayload.authTypes.push(AUTH_TYPES.TOTP);
        }
    }

    async verifyCredentials(user, loginData) {
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

    async setTotpSecret(user, secret) {
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

    async confirmTotpSetup(user, token) {
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

    async deleteTotp(user) {
        if (!user.totpEnabled && !user.totpPendingSetup) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.TOTP_NOT_ENABLED
            };
        }

        const hasOtherAuthMethods = user.authTypes && user.authTypes.length > 1;

        if (!hasOtherAuthMethods) {
            return {
                status: STATUS.FAILED,
                reason: ERROR_REASONS.CANNOT_DELETE_LAST_AUTH_METHOD
            };
        }

        user.totpSecret = undefined;
        user.totpEnabled = false;
        user.totpPendingSetup = false;

        if (user.authTypes) {
            const totpAuthIndex = user.authTypes.indexOf(AUTH_TYPES.TOTP);
            if (totpAuthIndex !== -1) {
                user.authTypes.splice(totpAuthIndex, 1);
            }
        }

        await this.persistence.updateUserLoginStatus(user.id, user);

        return {
            status: STATUS.SUCCESS,
            message: "TOTP authentication was successfully removed"
        };
    }
}

module.exports = TotpUserLoginStrategy; 