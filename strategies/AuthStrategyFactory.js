const EmailAuthStrategy = require('./EmailAuthStrategy');
const PasskeyAuthStrategy = require('./PasskeyAuthStrategy');
const TotpAuthStrategy = require('./TotpAuthStrategy');

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

        this.strategies.email = new EmailAuthStrategy(userLoginPlugin, emailPlugin);
        this.strategies.passkey = new PasskeyAuthStrategy(userLoginPlugin);
        this.strategies.totp = new TotpAuthStrategy(userLoginPlugin);
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
        const userInfo = await this.strategies.email.checkUserExists(email);

        return {
            strategy: this.getStrategy(userInfo.authType),
            userInfo: userInfo
        };
    }
}

const factory = new AuthStrategyFactory();

module.exports = factory; 