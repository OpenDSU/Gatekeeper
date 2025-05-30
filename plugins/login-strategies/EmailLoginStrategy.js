const UserLoginStrategyInterface = require('./LoginStrategyInterface');

const expiryTimeout = 5 * 60 * 1000;
const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../../constants/authConstants');
const crypto = require("crypto");

class EmailUserLoginStrategy extends UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        super(persistence, webauthnUtils, crypto, loginChallenges);
    }

    generateValidationCode(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const bytes = crypto.randomBytes(length)
        let code = '';

        for (let i = 0; i < length; i++) {
            // Map each random byte to a character in the `chars` string
            const randomIndex = bytes[i] % chars.length;
            code += chars[randomIndex];
        }

        return code;
    }

    async userExists(user) {
        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        return {
            authTypes: user.authTypes,
            activeAuthType: AUTH_TYPES.EMAIL
        };
    }

    async createUser(userPayload) {
        if (!userPayload.authTypes) {
            userPayload.authTypes = [AUTH_TYPES.EMAIL];
        } else if (!userPayload.authTypes.includes(AUTH_TYPES.EMAIL)) {
            userPayload.authTypes.push(AUTH_TYPES.EMAIL);
        }

        userPayload.validationEmailCode = this.generateValidationCode(5);
        userPayload.validationEmailCodeTimestamp = new Date().toISOString();
    }

    async verifyCredentials(user, loginData) {
        const code = loginData;
        let now = new Date().getTime();

        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        if (user.validationEmailCode === code) {
            if (!user.validationEmailCodeTimestamp || now - new Date(user.validationEmailCodeTimestamp).getTime() > expiryTimeout) {
                return { verified: false, reason: ERROR_REASONS.CODE_EXPIRED };
            }
            return {
                verified: true,
                update: {
                    validationEmailCode: undefined,
                    validationEmailCodeTimestamp: undefined
                }
            };
        } else {
            return { verified: false, reason: ERROR_REASONS.INVALID_CODE };
        }
    }

    async getEmailCode(user) {
        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        user.validationEmailCode = this.generateValidationCode(5);
        user.validationEmailCodeTimestamp = new Date().toISOString();
        await this.persistence.updateUserLoginStatus(user.id, user);
        return {
            userId: user.id,
            status: STATUS.SUCCESS,
            code: user.validationEmailCode,
            authTypes: user.authTypes
        };
    }
}

module.exports = EmailUserLoginStrategy; 
