const crypto = require("crypto");
const {AUTH_TYPES} = require("../constants/authConstants");
const webauthnUtils = require("../authenticator/webauthn");
const EmailUserLoginStrategy = require("../plugins/user-login-strategies/EmailUserLoginStrategy");
const PasskeyUserLoginStrategy = require("../plugins/user-login-strategies/PasskeyUserLoginStrategy");
const TotpUserLoginStrategy = require("../plugins/user-login-strategies/TotpUserLoginStrategy");



function generateId(length = 16) {
    let randomStringId = "";
    while (randomStringId.length < length) {
        randomStringId = crypto.randomBytes(length).toString("base64url").slice(0, length);
    }
    return randomStringId;
}

function generateWalletKey() {
    return crypto.createHash('sha256')
        .update(crypto.randomBytes(32))
        .digest('hex');
}

const loginChallenges = new Map();

function getLoginStrategy(authType = AUTH_TYPES.EMAIL, persistence) {
    switch (authType) {
        case AUTH_TYPES.EMAIL:
            return new EmailUserLoginStrategy(persistence, webauthnUtils, crypto, loginChallenges);
            break;
        case AUTH_TYPES.PASSKEY:
            return new PasskeyUserLoginStrategy(persistence, webauthnUtils, crypto, loginChallenges)
            break;
        case AUTH_TYPES.TOTP:
            return new TotpUserLoginStrategy(persistence, webauthnUtils, crypto, loginChallenges)
            break;
    }
}

module.exports = {
    generateId,
    generateWalletKey,
    getLoginStrategy
};
