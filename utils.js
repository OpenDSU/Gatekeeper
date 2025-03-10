//const openDSU = require('opendsu');
//const crypto = openDSU.loadAPI("crypto");
const crypto = require("crypto");
crypto.generateRandom = function (length) {
    return crypto.randomBytes(length);
};
crypto.getRandomSecret = function (length) {
    return crypto.randomBytes(length);
};
crypto.encodeBase58 = function (data) {
    return data.toString("base58");
};
function generateValidationCode(length) {
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
function generateId(length = 16) {
    let random = crypto.getRandomSecret(length);
    let randomStringId = "";
    while (randomStringId.length < length) {
        randomStringId = crypto.encodeBase58(random).slice(0, length);
    }
    return randomStringId;
}
module.exports = {
    generateValidationCode,
    generateId
};