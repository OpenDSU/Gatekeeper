const {generateValidationCode, generateId, generateWalletKey} = require('./utils/utils');
const expiryTimeout = 5 * 60 * 1000;
const maxLoginAttempts = 5;
async function UserLogin(){
    let self = {};
    let persistence = await $$.loadPlugin("StandardPersistence");
    self.userExists = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        if(user){
            return {
                status: "success",
                userExists: true
            }
        }
        return {
            status: "success",
            userExists: false
        }
    }
    self.createUser = async function (email) {
        let validationEmailCode = generateValidationCode(5);
        let walletKey = generateWalletKey();
        let user = await persistence.createUserLoginStatus({
            email: email,
            validationEmailCode: validationEmailCode,
            validationEmailCodeTimestamp: new Date().toISOString(),
            walletKey: walletKey
        });
        user.status = "success";
        return user;
    }
    self.logout = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.sessionIds = [];
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success"
        }
    }
    self.authorizeUser = async function(email, code){
        let userExists = await self.userExists(email);
        if (!userExists) {
            return {
                status: "failed",
                reason: "account doesn't exist"
            };
        }
        let user = await persistence.getUserLoginStatus(email);
        let now = new Date().getTime();
        //reset attempts as 30min passed
        if (user.loginAttempts >= maxLoginAttempts && user.lastLoginAttempt <= now - expiryTimeout) {
            await self.resetLoginAttempts(email);
        }

        if (user.loginAttempts >= maxLoginAttempts) {
            return {
                status: "failed",
                reason: "exceeded number of attempts",
                lockTime: user.lastLoginAttempt + expiryTimeout - now
            }
        }
        if(user.validationEmailCode === code){
            if(now - new Date(user.validationEmailCodeTimestamp).getTime() > expiryTimeout){
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
                sessionId: sessionId,
                email: email,
                walletKey: user.walletKey,
                userInfo: user.userInfo,
                userId: user.id
            };
        }

        await self.incrementLoginAttempts(email);
        user.lastLoginAttempt = now;
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "failed",
            reason: "invalid code"
        }
    }
    self.getUserValidationEmailCode = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        if(!user){
            user = await self.createUser(email);
            return {
                status: "success",
                code: user.validationEmailCode,
                walletKey: user.walletKey
            };
        }
        if (user.loginAttempts >= maxLoginAttempts) {
            if(user.lastLoginAttempt > new Date().getTime() - expiryTimeout){
                return {
                    status: "failed",
                    reason: "exceeded number of attempts",
                    lockTime: user.lastLoginAttempt + expiryTimeout - new Date().getTime()
                }
            }
            await self.resetLoginAttempts(email);
        }
        user.validationEmailCode = generateValidationCode(5);
        user.validationEmailCodeTimestamp = new Date().toISOString();
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success",
            code: user.validationEmailCode
        };

    };
    self.checkSessionId = async function(email, sessionId){
        let user = await persistence.getUserLoginStatus(email);
        if(user.sessionIds.includes(sessionId)){
            return {
                status: "success"
            };
        }
        return {
            status: "failed"
        }
    }
    self.getUserInfo = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        return {
            status: "success",
            userInfo: user.userInfo
        };
    }
    self.setUserInfo = async function(email, userInfo){
        let user = await persistence.getUserLoginStatus(email);
        user.userInfo = userInfo;
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success"
        }
    }
    self.incrementLoginAttempts = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        if(!user.loginAttempts){
            user.loginAttempts = 0;
        }
        user.loginAttempts++;
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success"
        }
    }
    self.resetLoginAttempts = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.loginAttempts = 0;
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success"
        }
    }
    self.shutDown = async function(){
        await persistence.shutDown();
        return {
            status: "success"
        }
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
    },
    getDependencies: function(){
        return ["StandardPersistence"];
    }
}