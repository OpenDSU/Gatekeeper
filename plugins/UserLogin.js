const {generateValidationCode, generateId} = require('../utils');
async function UserLogin(){
    let self = {};
    let persistence = await $$.loadPlugin("DefaultPersistence");
    self.userExists = async function(email){
        return await persistence.getUserLoginStatus(email) !== undefined;
    }
    self.createUser = async function (email) {
        let validationEmailCode = generateValidationCode(5);
        return await persistence.createUserLoginStatus({
            email: email,
            validationEmailCode: validationEmailCode
        });
    }
    self.logout = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.sessionIds = [];
        return await persistence.updateUserLoginStatus(user.id, user);
    }
    self.authorizeUser = async function(email, code){
        let user = await persistence.getUserLoginStatus(email);
        if(user.validationEmailCode === code){
            user.validationEmailCode = undefined;
            let sessionId = generateId(16);
            if(!user.sessionIds){
                user.sessionIds = [];
            }
            user.sessionIds.push(sessionId);
            await persistence.updateUserLoginStatus(user.id, user);
            return sessionId;
        }
    }
    self.generateAuthorizationCode = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.validationEmailCode = generateValidationCode(5);
        await persistence.updateUserLoginStatus(user.id, user);
        return user.validationEmailCode;
    }
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