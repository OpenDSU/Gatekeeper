const BaseAuthStrategy = require('./BaseAuthStrategy');
const otpauth = require('../authenticator/totp/otpauth/index.cjs');
const { AUTH_TYPES, STATUS, TOTP_SETTINGS } = require('../constants/authConstants');

class TotpAuthStrategy extends BaseAuthStrategy {
    constructor(userLoginPlugin) {
        super(userLoginPlugin);
        this.defaultAuthType = AUTH_TYPES.TOTP;
    }

    // eslint-disable-next-line no-unused-vars
    getAuthMetadata(userResponse) {
        return {};
    }

    async generateAuthData(data) {
        const { email, name, referrerId } = data;

        const result = await this.userLogin.createUser(email, name, referrerId, AUTH_TYPES.TOTP, null);

        if (result.status !== STATUS.SUCCESS) {
            throw new Error(result.reason || "Failed to create TOTP user.");
        }

        const secret = new otpauth.Secret();

        const totp = new otpauth.TOTP({
            issuer: TOTP_SETTINGS.ISSUER,
            label: email,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: secret
        });

        const otpUri = totp.toString();

        const secretResult = await this.userLogin.setTotpSecret(email, secret.base32);

        if (secretResult.status !== STATUS.SUCCESS) {
            throw new Error(secretResult.reason || "Failed to store TOTP secret");
        }

        return {
            status: STATUS.SUCCESS,
            message: "TOTP registration successful.",
            uri: otpUri,
            secret: secret.base32,
            walletKey: result.walletKey
        };
    }

    async login(loginData) {
        const { email, token } = loginData;

        const result = await this.userLogin.authorizeUser(email, token, undefined, AUTH_TYPES.TOTP);

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

        const result = await this.userLogin.createUser(email, name, referrerId, AUTH_TYPES.TOTP, null);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                walletKey: result.walletKey
            };
        } else {
            throw new Error(result.reason || "Failed to create TOTP user");
        }
    }

    async initiateTotpSetup(email) {
        const secret = new otpauth.Secret();

        const totp = new otpauth.TOTP({
            issuer: TOTP_SETTINGS.ISSUER,
            label: email,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: secret
        });

        const otpUri = totp.toString();

        const result = await this.userLogin.setTotpSecret(email, secret.base32);

        if (result.status === STATUS.SUCCESS) {
            return {
                status: STATUS.SUCCESS,
                uri: otpUri,
                secret: secret.base32
            };
        } else {
            throw new Error(result.reason || "Failed to store TOTP secret");
        }
    }

    async confirmTotpSetup(email, token) {
        const result = await this.userLogin.verifyAndEnableTotp(email, token);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                message: "TOTP enabled successfully"
            };
        } else {
            return {
                success: false,
                error: result.reason || "Invalid verification code"
            };
        }
    }

    async deleteTotp(email) {
        const result = await this.userLogin.deleteTotp(email);

        if (result.status === STATUS.SUCCESS) {
            return {
                success: true,
                message: result.message || "TOTP authentication removed successfully"
            };
        } else {
            return {
                success: false,
                error: result.reason || "Failed to remove TOTP authentication"
            };
        }
    }
}

module.exports = TotpAuthStrategy; 
