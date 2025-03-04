const lightDBFactory = require("./LightDBEnclaveFactory");
const https = require('https');

const interfaceDefinition = ["addAccount", "loginEvent"]

function getCookies(req) {
    const cookies = req.headers.cookie
        ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('=')))
        : {};
    return cookies
}

function getVersionlessSSI(email, password) {
    const openDSU = require('opendsu');
    const keySSISpace = openDSU.loadAPI("keyssi");
    const crypto = openDSU.loadAPI("crypto");
    let path = crypto.deriveEncryptionKey(`${email}${password}`, 3000);
    path = crypto.sha256(path);
    return keySSISpace.createVersionlessSSI(undefined, path, crypto.deriveEncryptionKey(password, 1000));
}

const lightDBEnclaveFactory = lightDBFactory.getLightDBEnclaveFactoryInstance();

async function getEnclaveInstance() {
    return await lightDBEnclaveFactory.createLightDBEnclaveAsync();
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

const validateEmail = function (email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        throw new Error("invalid email address");
    }
}


module.exports = {
    getCookies,
    getVersionlessSSI,
    getEnclaveInstance,
    validateEmail,
    generateRandomCode,
    interfaceDefinition
}
