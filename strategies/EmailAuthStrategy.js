const BaseAuthStrategy = require('./BaseAuthStrategy');
const logger = $$.getLogger("apis", "auth.email");
const process = require('process');
const { AUTH_TYPES, STATUS } = require('../constants/authConstants');

class EmailAuthStrategy extends BaseAuthStrategy {
    constructor(userLoginPlugin, emailPlugin) {
        super(userLoginPlugin);
        this.emailPlugin = emailPlugin;
        this.defaultAuthType = AUTH_TYPES.EMAIL;
    }

    // eslint-disable-next-line no-unused-vars
    getAuthMetadata(userResponse) {
        // Email auth doesn't need additional metadata beyond what the base class provides
        return {};
    }

    async generateAuthData(data) {
        const { email, name, referrerId } = data;
        const result = await this.userLogin.getUserValidationEmailCode(email, name, referrerId);

        if (result.status === STATUS.SUCCESS) {
            let responseMessage = { status: STATUS.SUCCESS };
            if (process.env.NODE_ENV === 'development' || data.origin === "http://localhost:8080") {
                responseMessage.code = result.code;
            } else if (this.emailPlugin) {
                try {
                    let subject = "Your authentication code";
                    let text = `Your authentication code is: ${result.code}`;
                    let html = `Your authentication code is: <strong>${result.code}</strong>`;
                    await this.emailPlugin.sendEmail(
                        result.userId,
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
        const { email, name, referrerId, origin } = userData;
        const creationResult = await this.userLogin.createUser(email, name, referrerId, AUTH_TYPES.EMAIL, null);

        if (creationResult.status === STATUS.SUCCESS) {
            if (this.emailPlugin && creationResult.validationEmailCode) {
                try {
                    let subject = "Your account validation code";
                    let text = `Your validation code is: ${creationResult.validationEmailCode}`;
                    let html = `Your validation code is: <strong>${creationResult.validationEmailCode}</strong>`;
                    await this.emailPlugin.sendEmail(
                        creationResult.globalUserId,
                        creationResult.email,
                        process.env.SENDGRID_SENDER_EMAIL,
                        subject,
                        text,
                        html
                    );
                    logger.info(`Sent validation code email to ${creationResult.email} after registration.`);
                } catch (err) {
                    logger.error(`Failed to send validation email to ${creationResult.email} after registration: ${err.message}`);
                }
            }

            let responseMessage = {
                success: true,
                userId: creationResult.globalUserId,
                email: creationResult.email,
                walletKey: creationResult.walletKey,
                sessionId: creationResult.sessionId
            };

            if (process.env.NODE_ENV === 'development' || origin === "http://localhost:8080") {
                if (creationResult.validationEmailCode) {
                    responseMessage.code = creationResult.validationEmailCode;
                }
            }

            return responseMessage;
        } else {
            throw new Error(creationResult.reason || "Failed to create user");
        }
    }
}

module.exports = EmailAuthStrategy; 
