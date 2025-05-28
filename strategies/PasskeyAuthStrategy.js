const BaseAuthStrategy = require('./BaseAuthStrategy');
const { AUTH_TYPES, STATUS } = require('../constants/authConstants');

class PasskeyAuthStrategy extends BaseAuthStrategy {
    constructor(userLoginPlugin) {
        super(userLoginPlugin);
        this.defaultAuthType = AUTH_TYPES.PASSKEY;
    }


    // eslint-disable-next-line no-unused-vars
    getAuthMetadata(_userResponse) {
        // The core passkey metadata (publicKeyCredentialRequestOptions, challengeKey)
        // is now expected to be populated by UserLogin.userExists itself and placed into its returned authMetadata.
        // This method is for any *additional* metadata this specific strategy instance might want to layer on top
        // when checkUserExists is called *on an instance of PasskeyAuthStrategy*.
        // For now, PasskeyAuthStrategy doesn't add anything extra here beyond what UserLogin.userExists provides.
        let metadata = {};
        // If there was a need to, for example, add a flag like `passkeyStrategyIsActiveContext: true`,
        // this would be the place.
        return metadata;
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
            result.success = true;
            return result;
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
