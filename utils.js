const crypto = require("crypto");
function generateValidationCode(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const bytes = crypto.randomBytes(length)
    let code = '';

    for (let i = 0; i < length; i++) {
        // Map each random byte to a character in the `chars` string
        const randomIndex = bytes[i] % chars.length;
        code += chars[randomIndex];
    }

    return code;
}
function generateId(length = 16) {
    let randomStringId = "";
    while (randomStringId.length < length) {
        randomStringId = crypto.randomBytes(length).toString("base64url").slice(0, length);
    }
    return randomStringId;
}
module.exports = {
    generateValidationCode,
    generateId
};