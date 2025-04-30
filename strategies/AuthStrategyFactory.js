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
     * @returns {Promise<Object>} The appropriate strategy and user info
     */
    async getStrategyForUser(email) {
        const userInfo = await this.strategies[AUTH_TYPES.EMAIL].checkUserExists(email);

        const authTypeToUse = userInfo.activeAuthType ||
            (userInfo.authTypes && userInfo.authTypes.length > 0 ?
                userInfo.authTypes[0] : AUTH_TYPES.EMAIL);

        return {
            strategy: this.getStrategy(authTypeToUse),
            userInfo: userInfo
        };
    }
}

const factory = new AuthStrategyFactory();

module.exports = factory; 