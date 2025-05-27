const { AUTH_TYPES } = require('../constants/authConstants');
/**
 * Base Authentication Strategy
 * 
 * This defines the common interface and base implementation that all authentication strategies must implement or extend.
 * Each method corresponds to a step in the authentication flow.
 */
class BaseAuthStrategy {
    constructor(userLoginPlugin) {
        this.userLogin = userLoginPlugin;
        this.defaultAuthType = null; // Should be overridden by subclasses
    }

    /**
     * Checks if a user exists and returns auth-specific options
     * @param {string} email - User email
     * @returns {Promise<Object>} Standard response with format:
     *   {
     *     userExists: boolean,
     *     activeAuthType: string,
     *     authTypes: string[],
     *     authMetadata: Object - merged auth-specific metadata for all auth types
     *   }
     */
    async checkUserExists(email) {
        const response = await this.userLogin.userExists(email); // This returns raw data from persistence + some strategy enrichments

        const collectedAuthMetadata = {};

        if (response.userExists) {
            // Collect metadata from the primary strategy determined by userLogin.userExists
            if (response.authMetadata) { // userLogin.userExists should provide enriched metadata
                Object.assign(collectedAuthMetadata, response.authMetadata);
            }

            // Ensure Passkey specific metadata is included if passkeys are available,
            // regardless of the activeAuthType, because UI might want to offer passkey login.
            if (response.authTypes && response.authTypes.includes(AUTH_TYPES.PASSKEY)) {
                // To get fresh passkey challenge options, we might need to call its strategy.
                // However, userLogin.userExists already calls the primary strategy's handleUserExists.
                // If primary is Passkey, it's already included. If not, we might need an explicit call or ensure userLogin.userExists provides it.

                // For now, let's assume response from userLogin.userExists contains the necessary raw fields if passkeys are present
                // (e.g., it might have run passkeyStrategy's handleUserExists internally if passkeys are found)
                if (response.publicKeyCredentialRequestOptions) {
                    collectedAuthMetadata.publicKeyCredentialRequestOptions = response.publicKeyCredentialRequestOptions;
                }
                if (response.challengeKey) {
                    collectedAuthMetadata.challengeKey = response.challengeKey;
                }
            }

            // Include TOTP status
            collectedAuthMetadata.totpEnabled = !!response.totpEnabled;
            collectedAuthMetadata.totpPendingSetup = !!response.totpPendingSetup;
        }

        // Allow the specific strategy instance (this) to add/override its own metadata
        const strategySpecificMetadata = this.getAuthMetadata(response); // Called on the specific strategy (e.g., EmailAuthStrategy)
        if (strategySpecificMetadata && Object.keys(strategySpecificMetadata).length > 0) {
            Object.assign(collectedAuthMetadata, strategySpecificMetadata);
        }

        return {
            userExists: response.userExists,
            activeAuthType: response.userExists ? response.activeAuthType : this.defaultAuthType,
            authTypes: response.authTypes || [this.defaultAuthType],
            authMetadata: collectedAuthMetadata
        };
    }

    /**
     * Get auth-specific metadata based on the user response
     * @param {Object} userResponse - The response from userLogin.userExists
     * @returns {Object} Auth-specific metadata
     */
    // eslint-disable-next-line no-unused-vars
    getAuthMetadata(userResponse) {
        return {}; // Default implementation returns empty object
    }

    /**
     * Generates authentication code or setup data for registration
     * @param {Object} data - Registration data
     * @returns {Promise<Object>} Results of auth code generation
     */
    // eslint-disable-next-line no-unused-vars
    async generateAuthData(data) {
        throw new Error('Method not implemented');
    }

    /**
     * Handles user login
     * @param {Object} loginData - Login credentials/data
     * @returns {Promise<Object>} Login result
     */
    // eslint-disable-next-line no-unused-vars
    async login(loginData) {
        throw new Error('Method not implemented');
    }

    /**
     * Creates a new user with this auth method
     * @param {Object} userData - User creation data
     * @returns {Promise<Object>} User creation result
     */
    // eslint-disable-next-line no-unused-vars
    async createUser(userData) {
        throw new Error('Method not implemented');
    }
}

module.exports = BaseAuthStrategy; 