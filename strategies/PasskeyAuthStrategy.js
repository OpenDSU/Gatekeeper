const BaseAuthStrategy = require('./BaseAuthStrategy');
const { AUTH_TYPES, STATUS } = require('../constants/authConstants');

class PasskeyAuthStrategy extends BaseAuthStrategy {
    constructor(userLoginPlugin) {
        super(userLoginPlugin);
        this.defaultAuthType = AUTH_TYPES.PASSKEY;
    }


    getAuthMetadata(userResponse) {
        let metadata = {};

        // Include passkey-specific fields even if passkey is not the active auth type
        if (userResponse.userExists) {
            if (userResponse.publicKeyCredentialRequestOptions) {
                metadata.publicKeyCredentialRequestOptions = userResponse.publicKeyCredentialRequestOptions;
            }
            if (userResponse.challengeKey) {
                metadata.challengeKey = userResponse.challengeKey;
            }
        }

        return metadata;
    }

    async generateAuthData(data) {
        const { email, name, referrerId, registrationData } = data;

        if (!registrationData) {
            throw new Error("Missing registrationData for passkey signup.");
        }

        const result = await this.userLogin.createUser(email, name, referrerId, AUTH_TYPES.PASSKEY, registrationData);

        if (result.status === STATUS.SUCCESS) {
            return {
                status: STATUS.SUCCESS,
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

    async deletePasskey(email, credentialId) {
        if (!credentialId) {
            throw new Error("Missing credential ID for passkey deletion.");
        }

        const result = await this.userLogin.deletePasskey(email, credentialId);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                message: result.message || "Passkey deleted successfully"
            };
        } else {
            return {
                success: false,
                error: result.reason || "Failed to delete passkey"
            };
        }
    }
}

module.exports = PasskeyAuthStrategy; 
