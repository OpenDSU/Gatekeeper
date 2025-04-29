const UserLoginStrategyInterface = require('./UserLoginStrategyInterface');
const { generateValidationCode } = require('../../utils/pluginUtils');
const expiryTimeout = 5 * 60 * 1000;
const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../../constants/authConstants');

class EmailUserLoginStrategy extends UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        super(persistence, webauthnUtils, crypto, loginChallenges);
    }

    async handleUserExists(user) {
        return { authType: AUTH_TYPES.EMAIL };
    }

    async handleCreateUser(userPayload, registrationData) {
        userPayload.validationEmailCode = generateValidationCode(5);
        userPayload.validationEmailCodeTimestamp = new Date().toISOString();
    }

    async handleAuthorizeUser(user, loginData, _challengeKey) {
        const code = loginData;
        let now = new Date().getTime();

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
        user.validationEmailCode = generateValidationCode(5);
        user.validationEmailCodeTimestamp = new Date().toISOString();
        await this.persistence.updateUserLoginStatus(user.id, user);
        return {
            status: STATUS.SUCCESS,
            code: user.validationEmailCode,
            authType: AUTH_TYPES.EMAIL
        };
    }
}

module.exports = EmailUserLoginStrategy; 