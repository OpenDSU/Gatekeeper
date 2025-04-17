const {generateValidationCode, generateId, generateWalletKey} = require('../utils/pluginUtils');
const expiryTimeout = 5 * 60 * 1000;
const maxLoginAttempts = 5;
async function UserLogin(){
    let self = {};
    let persistence = await $$.loadPlugin("StandardPersistence");
    let CreditManager = await $$.loadPlugin("CreditManager");
    const {verifyRegistrationResponse, verifyAssertionResponse} = require("../passkey/serverSideWebauthn");
    self.userExists = async function(email){
        let userExists = await persistence.hasUserLoginStatus(email);
        if (userExists) {
            let user = await persistence.getUserLoginStatus(email);
            if (user.authType === "passkey") {
                // passkey login flow start
                const parsedCredential = JSON.parse(user.validationEmailCode);
            
                const allowCredentials = [{
                    type: 'public-key',
                    id: parsedCredential.id,
                }];

                const challenge = require("crypto").randomBytes(32).toString("base64url");
                const loginChallengeKey = `login_${user.id}_${Date.now()}`;

                const publicKeyCredentialRequestOptions = {
                    challenge: challenge,
                    allowCredentials: allowCredentials,
                    rpId: process.env.RP_ID,
                    userVerification: 'required',
                    timeout: 60000,
                };

                user.challenge = challenge.toString('base64url');
                user.loginChallengeKey = loginChallengeKey;
                await persistence.updateUserLoginStatus(user.id, user);

                return {
                    status: "success",
                    userExists: true,
                    publicKeyCredentialRequestOptions: JSON.stringify(publicKeyCredentialRequestOptions),
                    loginChallengeKey: loginChallengeKey,
                    authType: user.authType
                }
            }
            return {
                status: "success",
                userExists: true,
                authType: user.authType
            }
        }
        return {
            status: "success",
            userExists: false
        }
    }

    self.createUser = async function (email, name, referrerId, authType, validationEmailCode) {
        let walletKey = generateWalletKey();
        name = name || email.split("@")[0];
        let userAsset = await CreditManager.addUser(email, name, referrerId);
        authType = authType || "email";
        if (authType === "email") {
            validationEmailCode = generateValidationCode(5);
        } else {
            const credentialInfo = await verifyRegistrationResponse(
                validationEmailCode,
                undefined,
                undefined,
                undefined,
                false
            );
            validationEmailCode = JSON.stringify({
                publicKey: credentialInfo.credentialPublicKey.toString('base64url'),
                aaguid: credentialInfo.aaguid.toString('base64url'),
                id: credentialInfo.credentialId.toString('base64url'),
                fmt: credentialInfo.attestationFormat,
                count: credentialInfo.signCount
            });
        }
        let user = await persistence.createUserLoginStatus({
            globalUserId: userAsset.id,
            email: email,
            validationEmailCode: validationEmailCode,
            validationEmailCodeTimestamp: new Date().toISOString(),
            walletKey: walletKey,
            authType: authType
        });
        user.status = "success";
        return user;
    }

    self.logout = async function(sessionId){
        //delete sessionObject here
        let sessionExists = await persistence.hasSession(sessionId);
        if(!sessionExists){
            return {
                status: "failed",
                reason: "session does not exist"
            }
        }
        await persistence.deleteSession(sessionId);
        return {
            status: "success"
        }
    }

    self.authorizeUser = async function(email, code){
        let userExists = await persistence.hasUserLoginStatus(email);
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
        if(user.authType === "passkey"){
            // passkey login end
            // code contains passkey
            // verify passkey
            return {
                status: "success",
                userExists: true,
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
            user.validationEmailCodeTimestamp = undefined;
            let sessionId = generateId(16);
            let session = await persistence.createSession({
                userLoginId: user.id,
                sessionId: sessionId
            });
            user.loginAttempts = 0;
            await persistence.updateUserLoginStatus(user.id, user);
            return {
                status: "success",
                sessionId: sessionId,
                email: email,
                walletKey: user.walletKey,
                userInfo: user.userInfo,
                userId: user.globalUserId
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
    self.getUserValidationEmailCode = async function(email, name, referrerId, authType, validationEmailCode){
        let user = await persistence.hasUserLoginStatus(email);
        if(!user){
            user = await self.createUser(email, name, referrerId, authType, validationEmailCode);
            return {
                status: "success",
                code: user.validationEmailCode,
                walletKey: user.walletKey
            };
        }
        user = await persistence.getUserLoginStatus(email);
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
    self.checkSessionId = async function(sessionId){
        let sessionExists = await persistence.hasSession(sessionId);
        if(!sessionExists){
            return {
                status: "failed",
                reason: "session does not exist"
            }
        }
        let session = await persistence.getSession(sessionId);
        let userExists = await persistence.hasUserLoginStatus(session.userLoginId);
        if (!userExists) {
            return {
                status: "failed",
                reason: "user doesn't exist"
            }
        }
        let user = await persistence.getUserLoginStatus(session.userLoginId);
        return {
            status: "success",
            globalUserId: user.globalUserId,
            email: user.email,
            walletKey: user.walletKey
        };

    }

    self.getUserInfo = async function(email){
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return {
                status: "failed",
                reason: "user doesn't exist"
            }
        }
        let user = await persistence.getUserLoginStatus(email);
        return {
            status: "success",
            userInfo: user.userInfo || {}
        };
    }

    self.setUserInfo = async function(email, userInfo){
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return {
                status: "failed",
                reason: "user doesn't exist"
            }
        }
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
        return ["StandardPersistence", "CreditManager"];
    }
}
