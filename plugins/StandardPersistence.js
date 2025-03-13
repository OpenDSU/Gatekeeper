const persisto = require("Persisto");
async function createStandardPersistencePlugin(){
    let persistence = await persisto.initialisePersisto();
    persistence.configureTypes({
        userLoginStatus: {
            globalUserId: "string",
            email: "string",
            loginAttempts: "integer",
            walletToken: "string",
            validationEmailCode: "string",
            sessionIds: "array",
            userInfo: "object",
            lastLoginAttempt: "string",
            validationEmailCodeTimestamp: "string"
        },
    });

    await persistence.createIndex("userLoginStatus", "email");

    return persistence;
}

let singleton = null;

module.exports = {
    getInstance: async function () {
        if(!singleton){
            singleton = await createStandardPersistencePlugin();
        }
        return singleton;
    },
    getAllow: function(){
        return async function(globalUserId, email, command, ...args){
            return false;
        }
    }
}