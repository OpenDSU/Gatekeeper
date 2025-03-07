
const extensiblePersistenceModule = require('../ExtensiblePersistence');

async function createStandardPersistencePlugin(){
    const autoSaver = await extensiblePersistenceModule.getAutoSaverPersistence();
    let persistence = await extensiblePersistenceModule.getPersistentStorage(autoSaver, systemLogger, {
        userLoginStatus: {
            globalUserId: "string",
            email: "string",
            loginAttempts: "integer",
            walletToken: "string",
            validationEmailCode: "string",
            sessionIds: "array",
            userInfo: "object",
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