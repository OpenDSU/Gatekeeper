const EmailAuthStrategy = require('./EmailAuthStrategy');
const PasskeyAuthStrategy = require('./PasskeyAuthStrategy');
const TotpAuthStrategy = require('./TotpAuthStrategy');
const { AUTH_TYPES } = require('../constants/authConstants');
/**
 * Factory for creating authentication strategy objects
 */
class AuthStrategyFactory {
    constructor() {
        this.strategies = {};
        this.userLoginPlugin = null;
        this.emailPlugin = null;
    }

    /**
     * Initialize the factory with required plugins
     * @param {Object} userLoginPlugin - The UserLogin plugin instance
     * @param {Object} emailPlugin - The Email plugin instance
     */
    init(userLoginPlugin, emailPlugin) {
        this.userLoginPlugin = userLoginPlugin;
        this.emailPlugin = emailPlugin;

        this.strategies[AUTH_TYPES.EMAIL] = new EmailAuthStrategy(userLoginPlugin, emailPlugin);
        this.strategies[AUTH_TYPES.PASSKEY] = new PasskeyAuthStrategy(userLoginPlugin);
        this.strategies[AUTH_TYPES.TOTP] = new TotpAuthStrategy(userLoginPlugin);
    }

    /**
     * Get the appropriate strategy based on auth type
     * @param {string} authType - The authentication type (email, passkey, totp)
     * @returns {Object} The authentication strategy
     */
    getStrategy(authType) {
        if (!this.strategies[authType]) {
            throw new Error(`Unsupported authentication strategy: ${authType}`);
        }
        return this.strategies[authType];
    }

    /**
     * Determine the best strategy for a user based on email lookup
     * @param {string} email - The user's email address
     * @param {string} loginMethod - Optional preferred login method
     * @returns {Promise<Object>} The appropriate strategy
     */
    async getStrategyForUser(email, loginMethod) {
        // directly use userLoginPlugin to get comprehensive user info first
        // This avoids depending on a specific strategy (like email) to fetch initial user state.
        const userLoginExistsResponse = await this.userLoginPlugin.userExists(email);

        if (!userLoginExistsResponse.userExists) {
            // If user doesn't exist, default to email strategy for signup/initial interaction
            return this.getStrategy(AUTH_TYPES.EMAIL);
        }

        if (loginMethod &&
            userLoginExistsResponse.authTypes &&
            userLoginExistsResponse.authTypes.includes(loginMethod)) {
            return this.getStrategy(loginMethod);
        }

        // Fallback to activeAuthType or the first in authTypes list
        const authTypeToUse = userLoginExistsResponse.activeAuthType ||
            (userLoginExistsResponse.authTypes && userLoginExistsResponse.authTypes.length > 0 ?
                userLoginExistsResponse.authTypes[0] : AUTH_TYPES.EMAIL);

        return this.getStrategy(authTypeToUse);
    }
}

const factory = new AuthStrategyFactory();

module.exports = factory; 