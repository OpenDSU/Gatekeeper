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
        const response = await this.userLogin.userExists(email);

        const authMetadata = {};

        if (response.userExists) {
            if (response.publicKeyCredentialRequestOptions) {
                authMetadata.publicKeyCredentialRequestOptions = response.publicKeyCredentialRequestOptions;
            }
            if (response.challengeKey) {
                authMetadata.challengeKey = response.challengeKey;
            }

            authMetadata.totpEnabled = !!response.totpEnabled;
            authMetadata.totpPendingSetup = !!response.totpPendingSetup;
        }

        const strategyMetadata = this.getAuthMetadata(response);
        if (strategyMetadata && Object.keys(strategyMetadata).length > 0) {
            Object.assign(authMetadata, strategyMetadata);
        }

        return {
            userExists: response.userExists,
            activeAuthType: response.userExists ? response.activeAuthType : this.defaultAuthType,
            authTypes: response.authTypes || [this.defaultAuthType],
            authMetadata
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