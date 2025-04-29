/**
 * Authentication Strategy Interface
 * 
 * This defines the common interface that all authentication strategies must implement.
 * Each method corresponds to a step in the authentication flow.
 */
class AuthStrategyInterface {
    /**
     * Checks if a user exists and returns auth-specific options
     * @param {string} email - User email
     * @returns {Promise<Object>} User existence status and auth options
     */
    async checkUserExists(email) {
        throw new Error('Method not implemented');
    }

    /**
     * Generates authentication code or setup data for registration
     * @param {Object} data - Registration data
     * @returns {Promise<Object>} Results of auth code generation
     */
    async generateAuthData(data) {
        throw new Error('Method not implemented');
    }

    /**
     * Handles user login
     * @param {Object} loginData - Login credentials/data
     * @returns {Promise<Object>} Login result
     */
    async login(loginData) {
        throw new Error('Method not implemented');
    }

    /**
     * Creates a new user with this auth method
     * @param {Object} userData - User creation data
     * @returns {Promise<Object>} User creation result
     */
    async createUser(userData) {
        throw new Error('Method not implemented');
    }
}

module.exports = AuthStrategyInterface; 