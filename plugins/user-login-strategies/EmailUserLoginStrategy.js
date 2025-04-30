const UserLoginStrategyInterface = require('./UserLoginStrategyInterface');
const { generateValidationCode } = require('../../utils/pluginUtils');
const expiryTimeout = 5 * 60 * 1000;
const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../../constants/authConstants');

class EmailUserLoginStrategy extends UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        super(persistence, webauthnUtils, crypto, loginChallenges);
    }

    async handleUserExists(user) {
        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        return {
            authTypes: user.authTypes,
            activeAuthType: AUTH_TYPES.EMAIL
        };
    }

    async handleCreateUser(userPayload) {
        if (!userPayload.authTypes) {
            userPayload.authTypes = [AUTH_TYPES.EMAIL];
        } else if (!userPayload.authTypes.includes(AUTH_TYPES.EMAIL)) {
            userPayload.authTypes.push(AUTH_TYPES.EMAIL);
        }

        userPayload.validationEmailCode = generateValidationCode(5);
        userPayload.validationEmailCodeTimestamp = new Date().toISOString();
    }

    async handleAuthorizeUser(user, loginData) {
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

    async handleGetUserValidationCode(user) {
        if (!user.authTypes) {
            user.authTypes = user.activeAuthType ? [user.activeAuthType] : [AUTH_TYPES.EMAIL];
        }

        user.validationEmailCode = generateValidationCode(5);
        user.validationEmailCodeTimestamp = new Date().toISOString();
        await this.persistence.updateUserLoginStatus(user.id, user);
        return {
            status: STATUS.SUCCESS,
            code: user.validationEmailCode,
            authTypes: user.authTypes
        };
    }
}

module.exports = EmailUserLoginStrategy; 