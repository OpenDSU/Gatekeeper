/**
 * Internal UserLogin Strategy Interface
 * 
 * Defines core methods that all authentication strategies must implement.
 */
const { ERROR_REASONS } = require('../../constants/authConstants');

class UserLoginStrategyInterface {
    constructor(persistence, webauthnUtils, crypto, loginChallenges) {
        this.persistence = persistence;
        this.webauthnUtils = webauthnUtils; // { verifyRegistrationResponse, verifyAssertionResponse }
        this.crypto = crypto;
        this.loginChallenges = loginChallenges;
        this.otpauth = require('../../authenticator/totp/otpauth/index.cjs');
    }

    /**
     * Handles specific logic for userExists based on auth type.
     * @param {Object} user - The user object from persistence.
     * @returns {Promise<Object>} Auth-specific data for userExists response.
     */
    async userExists(user) {
        throw new Error(ERROR_REASONS.METHOD_NOT_IMPLEMENTED);
    }

    /**
     * Modifies the user payload during creation based on auth type.
     * @param {Object} userPayload - The initial user payload.
     * @param {any} registrationData - Optional registration data (e.g., for passkey).
     * @returns {Promise<void>} 
     */
    async createUser(userPayload, registrationData) {
        throw new Error(ERROR_REASONS.METHOD_NOT_IMPLEMENTED);
    }

    /**
     * Verifies user credentials during login based on auth type.
     * @param {Object} user - The user object from persistence.
     * @param {any} loginData - The login data provided by the user (e.g., code, assertion).
     * @param {string} [challengeKey] - Optional challenge key (for passkey).
     * @returns {Promise<{verified: boolean, reason?: string, update?: Object}>} 
     *          - verified: boolean indicating success.
     *          - reason: string explaining failure.
     *          - update: object with changes to apply to the user object on success (e.g., signCount).
     */
    async verifyCredentials(user, loginData, challengeKey) {
        throw new Error(ERROR_REASONS.METHOD_NOT_IMPLEMENTED);
    }
}

module.exports = UserLoginStrategyInterface; 