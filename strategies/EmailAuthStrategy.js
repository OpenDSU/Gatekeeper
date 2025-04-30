const AuthStrategyInterface = require('./AuthStrategyInterface');
const logger = $$.getLogger("apis", "auth.email");
const process = require('process');
const { AUTH_TYPES, STATUS } = require('../constants/authConstants');
class EmailAuthStrategy extends AuthStrategyInterface {
    constructor(userLoginPlugin, emailPlugin) {
        super();
        this.userLogin = userLoginPlugin;
        this.emailPlugin = emailPlugin;
    }

    async checkUserExists(email) {
        const response = await this.userLogin.userExists(email);
        if (response.userExists && response.activeAuthType === AUTH_TYPES.EMAIL) {
            return {
                userExists: true,
                activeAuthType: AUTH_TYPES.EMAIL
            };
        } else if (response.userExists) {
            return {
                userExists: true,
                activeAuthType: response.activeAuthType
            };
        }
        return {
            userExists: false,
            activeAuthType: AUTH_TYPES.EMAIL
        };
    }

    async generateAuthData(data) {
        const { email, name, referrerId } = data;
        const result = await this.userLogin.getUserValidationEmailCode(email, name, referrerId);

        if (result.status === STATUS.SUCCESS) {
            let responseMessage = { result: STATUS.SUCCESS };
            if (process.env.NODE_ENV === 'development' || data.origin === "http://localhost:8080") {
                responseMessage.code = result.code;
            } else if (this.emailPlugin) {
                try {
                    let subject = "Your authentication code";
                    let text = `Your authentication code is: ${result.code}`;
                    let html = `Your authentication code is: <strong>${result.code}</strong>`;
                    await this.emailPlugin.sendEmail(
                        email,
                        process.env.SENDGRID_SENDER_EMAIL,
                        subject,
                        text,
                        html
                    );
                    logger.info(`Sent auth code email to ${email}`);
                } catch (err) {
                    logger.error(`Failed to send email to ${email}: ${err.message}`);
                }
            }
            return responseMessage;
        } else {
            throw new Error(result.reason || "Failed to generate auth code");
        }
    }

    async login(loginData) {
        const { email, code } = loginData;
        const result = await this.userLogin.authorizeUser(email, code, undefined, AUTH_TYPES.EMAIL);

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
        const { email, name, referrerId } = userData;
        const result = await this.userLogin.createUser(email, name, referrerId, AUTH_TYPES.EMAIL, null);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                walletKey: result.walletKey
            };
        } else {
            throw new Error(result.reason || "Failed to create user");
        }
    }
}

module.exports = EmailAuthStrategy; 
