
async function UserLogin(){
    let self = {};
    let persistence = await $$.loadPlugin("DefaultPersistence");

    self.createUser = async function (email) {
        //create here: validationEmailCode is a random string that will be sent to the user's email
        let validationEmailCode;
        return await persistence.createUser({
            email: email,
            validationEmailCode: validationEmailCode
        });
    }
    self.logout = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.sessionIds = [];
        return await persistence.updateUserLoginStatus(email, user);
    }
    self.authorizeUser = async function(email, code){
        let user = await persistence.getUserLoginStatus(email);
        if(user.validationEmailCode === code){
            user.validationEmailCode = undefined;
            let sessionId;
            user.sessionIds.push(sessionId);
            return await persistence.updateUserLoginStatus(email, user);
        }
        return false;
    }
    self.generateAuthorizationCode = async function(email){
        let user = await persistence.getUserLoginStatus(email);
        user.validationEmailCode;
        return await persistence.updateUserLoginStatus(email, user);
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
        return await persistence.updateUserLoginStatus(email, user);
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