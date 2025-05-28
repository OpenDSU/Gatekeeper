/**
 * Internal UserLogin Strategy Interface
 * 
 * Defines methods for handling authentication-type-specific logic within UserLogin.js.
 */
const { AUTH_TYPES, STATUS, ERROR_REASONS } = require('../../constants/authConstants');

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
     * @param {Object} _user - The user object from persistence.
     * @returns {Promise<Object>} Auth-specific data for userExists response.
     */
    async handleUserExists(_user) {
        return { authType: _user?.activeAuthType || AUTH_TYPES.EMAIL };
    }

    /**
     * Modifies the user payload during creation based on auth type.
     * @param {Object} _userPayload - The initial user payload.
     * @param {any} _registrationData - Optional registration data (e.g., for passkey).
     * @returns {Promise<void>} 
     */
    // eslint-disable-next-line no-unused-vars
    async handleCreateUser(_userPayload, _registrationData) {
        return Promise.resolve();
    }

    /**
     * Verifies user credentials during login based on auth type.
     * @param {Object} _user - The user object from persistence.
     * @param {any} _loginData - The login data provided by the user (e.g., code, assertion).
     * @param {string} [_challengeKey] - Optional challenge key (for passkey).
     * @returns {Promise<{verified: boolean, reason?: string, update?: Object}>} 
     *          - verified: boolean indicating success.
     *          - reason: string explaining failure.
     *          - update: object with changes to apply to the user object on success (e.g., signCount).
     */
    // eslint-disable-next-line no-unused-vars
    async handleAuthorizeUser(_user, _loginData, _challengeKey) {
        throw new Error(ERROR_REASONS.METHOD_NOT_IMPLEMENTED);
    }

    /**
     * Handles specific logic for getEmailCode based on auth type.
     * @param {Object} _user - The user object from persistence.
     * @returns {Promise<Object>} Result object, potentially indicating failure for non-email types.
     */
    // eslint-disable-next-line no-unused-vars
    async handleGetEmailCode(_user) {
        return { status: STATUS.FAILED, reason: ERROR_REASONS.OPERATION_NOT_SUPPORTED };
    }

    /**
     * Handles registration of a new passkey (specific to PasskeyStrategy).
     * @param {Object} _user - The user object from persistence.
     * @param {Object} _registrationData - Passkey registration data.
     * @returns {Promise<Object>} Result of the registration attempt.
     */
    // eslint-disable-next-line no-unused-vars
    async handleRegisterNewPasskey(_user, _registrationData) {
        throw new Error(ERROR_REASONS.METHOD_NOT_APPLICABLE);
    }

    /**
     * Handles setting the TOTP secret (specific to TotpStrategy).
     * @param {Object} _user - The user object from persistence.
     * @param {string} _secret - The TOTP secret (base32).
     * @returns {Promise<void>}
     */
    // eslint-disable-next-line no-unused-vars
    async handleSetTotpSecret(_user, _secret) {
        throw new Error(ERROR_REASONS.METHOD_NOT_APPLICABLE);
    }

    /**
     * Handles verifying and enabling TOTP (specific to TotpStrategy).
     * @param {Object} _user - The user object from persistence.
     * @param {string} _token - The TOTP token provided by the user.
     * @returns {Promise<{verified: boolean, reason?: string}>}
     */
    // eslint-disable-next-line no-unused-vars
    async handleVerifyAndEnableTotp(_user, _token) {
        throw new Error(ERROR_REASONS.METHOD_NOT_APPLICABLE);
    }
}

module.exports = UserLoginStrategyInterface; 