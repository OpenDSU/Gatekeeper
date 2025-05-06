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
        const userInfo = await this.strategies[AUTH_TYPES.EMAIL].checkUserExists(email);

        if (loginMethod &&
            userInfo.authTypes &&
            userInfo.authTypes.includes(loginMethod)) {
            return this.getStrategy(loginMethod);
        }

        if (loginMethod === AUTH_TYPES.EMAIL) {
            return this.getStrategy(AUTH_TYPES.EMAIL);
        }

        const authTypeToUse = userInfo.activeAuthType ||
            (userInfo.authTypes && userInfo.authTypes.length > 0 ?
                userInfo.authTypes[0] : AUTH_TYPES.EMAIL);

        return this.getStrategy(authTypeToUse);
    }
}

const factory = new AuthStrategyFactory();

module.exports = factory; 