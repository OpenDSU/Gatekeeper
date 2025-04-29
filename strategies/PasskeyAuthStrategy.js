const AuthStrategyInterface = require('./AuthStrategyInterface');
const { AUTH_TYPES, STATUS } = require('../constants/authConstants');

class PasskeyAuthStrategy extends AuthStrategyInterface {
    constructor(userLoginPlugin) {
        super();
        this.userLogin = userLoginPlugin;
    }

    async checkUserExists(email) {
        const response = await this.userLogin.userExists(email);

        if (response.userExists && response.authType === AUTH_TYPES.PASSKEY) {
            return {
                userExists: true,
                authType: AUTH_TYPES.PASSKEY,
                publicKeyCredentialRequestOptions: response.publicKeyCredentialRequestOptions,
                challengeKey: response.challengeKey
            };
        } else if (response.userExists) {
            return {
                userExists: true,
                authType: response.authType
            };
        }
        return {
            userExists: false,
            authType: AUTH_TYPES.PASSKEY
        };
    }

    async generateAuthData(data) {
        const { email, name, referrerId, registrationData } = data;

        if (!registrationData) {
            throw new Error("Missing registrationData for passkey signup.");
        }

        const result = await this.userLogin.createUser(email, name, referrerId, AUTH_TYPES.PASSKEY, registrationData);

        if (result.status === STATUS.SUCCESS) {
            return {
                result: STATUS.SUCCESS,
                message: "Passkey registration successful.",
                walletKey: result.walletKey
            };
        } else {
            throw new Error(result.reason || "Failed to register passkey");
        }
    }

    async login(loginData) {
        const { email, assertion, challengeKey } = loginData;
        const result = await this.userLogin.authorizeUser(email, assertion, challengeKey, AUTH_TYPES.PASSKEY);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                userId: result.userId,
                email: result.email,
                walletKey: result.walletKey,
                sessionId: result.sessionId
            };
        } else {
            return {
                success: false,
                error: result.reason,
                lockTime: result.lockTime
            };
        }
    }

    async createUser(userData) {
        const { email, name, referrerId, registrationData } = userData;

        if (!registrationData) {
            throw new Error("Missing registrationData for passkey user creation.");
        }

        const result = await this.userLogin.createUser(email, name, referrerId, AUTH_TYPES.PASSKEY, registrationData);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                walletKey: result.walletKey
            };
        } else {
            throw new Error(result.reason || "Failed to create passkey user");
        }
    }

    async registerNewPasskey(email, registrationData) {
        if (!registrationData) {
            throw new Error("Missing registrationData for additional passkey.");
        }

        const result = await this.userLogin.registerNewPasskey(email, registrationData);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                credentialId: result.credentialId
            };
        } else {
            throw new Error(result.reason || "Failed to register additional passkey");
        }
    }
}

module.exports = PasskeyAuthStrategy; 