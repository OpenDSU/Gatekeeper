const {generateValidationCode, generateId} = require('../utils');
async function UserLogin(){
    let self = {};
    let persistence = await $$.loadPlugin("DefaultPersistence");
    self.userExists = async function(email){
        return await persistence.getUserLoginStatus(email) !== undefined;
    }
    self.createUser = async function (email) {
        let validationEmailCode = generateValidationCode(5);
        let walletKey = crypto.sha256(crypto.generateRandom(32));
        return await persistence.createUserLoginStatus({
            email: email,
            validationEmailCode: validationEmailCode,
            validationEmailCodeTimestamp: new Date().toISOString(),
        });
    }
    self.logout = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.sessionIds = [];
        return await persistence.updateUserLoginStatus(user.id, user);
    }
    self.authorizeUser = async function(email, code, expiryTimeout){
        let user = await persistence.getUserLoginStatus(email);
        if(user.validationEmailCode === code){
            if(new Date().getTime() - new Date(user.validationEmailCodeTimestamp).getTime() > expiryTimeout){
                return {
                    status: "failed",
                    reason: "code expired"
                }
            }
            user.validationEmailCode = undefined;
            let sessionId = generateId(16);
            if(!user.sessionIds){
                user.sessionIds = [];
            }
            user.sessionIds.push(sessionId);
            user.loginAttempts = 0;
            await persistence.updateUserLoginStatus(user.id, user);
            return {
                status: "success",
                sessionId: sessionId
            };
        } else {
            return {
                status: "failed",
                reason: "invalid code"
            }
        }
    }
    self.generateAuthorizationCode = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.validationEmailCode = generateValidationCode(5);
        await persistence.updateUserLoginStatus(user.id, user);
        return user.validationEmailCode;
    }
    self.getUserValidationEmailCode = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        if(user){
            return user.validationEmailCode;
        }
    };
    self.checkSessionId = async function(email, sessionId){
        let user = await persistence.getUserLoginStatus(email);
        return user.sessionIds.includes(sessionId);
    }
    self.getUserInfo = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        return user.userInfo;
    }
    self.setUserInfo = async function(email, userInfo){
        let user = await persistence.getUserLoginStatus(email);
        user.userInfo = userInfo;
        return await persistence.updateUserLoginStatus(user.id, user);
    }
    self.getLoginAttempts = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        return user.loginAttempts;
    };
    self.incrementLoginAttempts = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        if(!user.loginAttempts){
            user.loginAttempts = 0;
        }
        user.loginAttempts++;
        return await persistence.updateUserLoginStatus(user.id, user);
    }
    self.resetLoginAttempts = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.loginAttempts = 0;
        return await persistence.updateUserLoginStatus(user.id, user);
    }
    self.getLastLoginAttempt = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        return user.lastLoginAttempt;
    };
    self.setLastLoginAttempt = async function(email, date){
        let user = await persistence.getUserLoginStatus(email);
        user.lastLoginAttempt = date;
        return await persistence.updateUserLoginStatus(user.id, user);
    }
    return self;
}

let singletonInstance = undefined;

module.exports = {
    getInstance: async function () {
        if(!singletonInstance){
            singletonInstance = await UserLogin();
        }
        return singletonInstance;
    },
    getAllow: function(){
        return async function(globalUserId, email, command, ...args){
            return true;
        }
    }
}