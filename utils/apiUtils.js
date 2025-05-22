function getCookies(req) {
    return req.headers.cookie
        ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('=')))
        : {}
}

function getVersionlessSSI(email, password) {
    const openDSU = require('opendsu');
    const keySSISpace = openDSU.loadAPI("keyssi");
    const crypto = openDSU.loadAPI("crypto");
    let path = crypto.deriveEncryptionKey(`${email}${password}`, 3000);
    path = crypto.sha256(path);
    return keySSISpace.createVersionlessSSI(undefined, path, crypto.deriveEncryptionKey(password, 1000));
}

function validateEmail(email) {
    const emailRegex = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return emailRegex.test(email);
}
function createAuthCookies(userId, email, walletKey, sessionId) {
    return [`userId=${userId}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`,
    `email=${encodeURIComponent(email)}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`,
    `walletKey=${walletKey}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`,
    `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`];
}

module.exports = {
    getCookies,
    getVersionlessSSI,
    validateEmail,
    createAuthCookies
}
