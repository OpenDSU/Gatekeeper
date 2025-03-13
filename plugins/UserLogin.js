const {generateValidationCode, generateId, generateWalletKey} = require('../utils');
const expiryTimeout = 5 * 60 * 1000;
const maxLoginAttempts = 5;
async function UserLogin(){
    let self = {};
    let persistence = await $$.loadPlugin("StandardPersistence");
    self.userExists = async function(email){
        return await persistence.getUserLoginStatus(email) !== undefined;
    }
    self.createUser = async function (email) {
        let validationEmailCode = generateValidationCode(5);
        let walletKey = generateWalletKey();
        return await persistence.createUserLoginStatus({
            email: email,
            validationEmailCode: validationEmailCode,
            validationEmailCodeTimestamp: new Date().toISOString(),
            walletKey: walletKey
        });
    }
    self.logout = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.sessionIds = [];
        return await persistence.updateUserLoginStatus(user.id, user);
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
    self.generateAuthorizationCode = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.validationEmailCode = generateValidationCode(5);
        await persistence.updateUserLoginStatus(user.id, user);
        return user.validationEmailCode;
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
        return {
            status: "success",
            code: user.validationEmailCode
        };

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
    self.getUserInfo = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        return user.userInfo;
    }
    self.setUserInfo = async function (email, userInfo){
        let user = await persistence.getUserLoginStatus(email);
        user.userInfo = userInfo;
        return await persistence.updateUserLoginStatus(user.id, user);
    }
    self.shutDown = async function(){
        await persistence.shutDown();
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