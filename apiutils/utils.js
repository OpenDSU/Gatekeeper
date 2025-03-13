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

function generateRandomCode(length) {
    const openDSU = require('opendsu');
    const resolver = openDSU.loadAPI("resolver");
    const crypto = openDSU.loadAPI("crypto");
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const bytes = crypto.generateRandom(length)
    let code = '';

    for (let i = 0; i < length; i++) {
        // Map each random byte to a character in the `chars` string
        const randomIndex = bytes[i] % chars.length;
        code += chars[randomIndex];
    }

    return code;
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
function createAuthCookies(userId, email, walletKey, userInfo) {
    return [`userId=${userId}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`,
        `email=${email}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`,
        `walletKey=${walletKey}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`,
        `userInfo=${JSON.stringify(userInfo)}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`]
}

module.exports = {
    getCookies,
    getVersionlessSSI,
    validateEmail,
    createAuthCookies
}
