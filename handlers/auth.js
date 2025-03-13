const logger = $$.getLogger("apis", "auth");
const path = require("path");
const fs = require("fs");
const sgMail = require("@sendgrid/mail");
const openDSU = require('opendsu');
const resolver = openDSU.loadAPI("resolver");
const crypto = openDSU.loadAPI("crypto");

const AUTH_CODES_TABLE = "auth_codes_table";
const {getVersionlessSSI, getEnclaveInstance, generateRandomCode, validateEmail, interfaceDefinition} = require("./../apiutils/utils");
const {getCookies} = require("../apiutils/utils");
const USER_LOGIN_PLUGIN = "UserLogin";

async function initAPIcClient(userId, serverUrl){
    let client = require("opendsu").loadAPI("serverless").createServerlessAPIClient(userId, serverUrl, USER_LOGIN_PLUGIN);
    await client.registerPlugin(USER_LOGIN_PLUGIN, path.join(__dirname, "..", "plugins", "UserLogin.js"));
    return client;
}
const accountExists = async function (req, res) {
    let response;
    try {
        let {email} = req.params;
        email = decodeURIComponent(email);
        validateEmail(email);
        let client = await initAPIcClient(req.userId, req.serverlessUrl);
        response = await client.accountExists(email);
    } catch (err) {
        logger.debug(err.message);
        res.writeHead(500, {'Content-Type': 'application/json'});
        return res.end(JSON.stringify({error: err.message}));
    }
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({account_exists: !!response}));
}

const generateAuthCode = async function (req, res) {
    let authData = req.body;
    try {
        authData = JSON.parse(authData);
        //TODO validate code
    } catch (e) {
        res.writeHead(415, {'Content-Type': 'application/json'});
        logger.debug(e.message);
        res.end(JSON.stringify({error: "Wrong data"}));
        return;
    }
    let client = await initAPIcClient(req.userId, req.serverlessUrl);

    try {
        let {email, refererId} = authData;
        validateEmail(email);

        let code = client.getUserValidationEmailCode(email);
        if (!code) {
            let user = await client.createUser(email);
            code = user.validationEmailCode;
        } else {
            let loginAttempts = await client.getLoginAttempts(email);
            let lastAttempt = await client.getLastLoginAttempt(email);
            if (loginAttempts >= 5) {
                if(lastAttempt > new Date().getTime() - 30 * 60 * 1000){
                    await client.loginEvent(req.userId, "FAIL", `Exceeded number of attempts`);
                    logger.debug(`Exceeded number of attempts in generateAuthCode: ${JSON.stringify(authData)}`);
                    res.writeHead(403, {'Content-Type': 'application/json'});
                    res.end(JSON.stringify({
                        error: "Exceeded number of attempts",
                        details: {
                            lockTime: lastAttempt + 30 * 60 * 1000 - new Date().getTime()
                        }
                    }));
                    return;
                } else {
                    await client.resetLoginAttempts(email);
                }
            }
        }

        let resultObj = {result: "success"};
        if (req.headers.origin === "http://localhost:8080") {
            resultObj.code = code;
        } else {
            const msg = {
                "to": email,
                "subject": "Your Hatefinity authentication code",
                "text": `Your authentication code is: ${code}`,
                "html": `Your authentication code is: <strong>${code}</strong>`,
            }
            client.sendMail(msg)
        }
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify(resultObj));
    } catch (e) {
        res.writeHead(500, {'Content-Type': 'application/json'});
        logger.debug(e.message);
        res.end(JSON.stringify({error: "Operation failed"}));
    }
}

const walletLogin = async (req, res) => {
    let loginData = req.body;
    try {
        loginData = JSON.parse(loginData);
        loginData.code = loginData.code.trim();
        //TODO validate code
    } catch (e) {
        res.writeHead(415, {'Content-Type': 'application/json'});
        logger.debug(e.message);
        res.end(JSON.stringify({error: "Wrong data"}));
        return;
    }
    try {
        validateEmail(loginData.email);
        let client = await initAPIcClient(req.userId, req.serverlessUrl);

        let accountExists = await client.accountExists(loginData.email);
        if (!accountExists) {
            logger.debug(`Account doesn't exist: ${JSON.stringify(loginData)}`);
            res.writeHead(401, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({error: "Invalid credentials"}));
            return;
        }
        let loginAttempts = await client.getLoginAttempts(loginData.email);
        if (!loginAttempts || loginAttempts < 5) {
            let sessionId = await client.authorizeUser(loginData.email, loginData.code);
            if(!sessionId){
                await client.incrementLoginAttempts(loginData.email);
                let lastAttempt = new Date().getTime();
                await client.setLastLoginAttempt(loginData.email, lastAttempt);
                await client.loginEvent(req.userId, "FAIL", `Invalid code`);
                logger.debug(`Invalid code: ${JSON.stringify(loginData)}`);
                res.writeHead(401, {'Content-Type': 'application/json'});
                res.end(JSON.stringify({error: "Invalid credentials"}));
                return;
            } else {
                //await client.loginEvent(result.id, "SUCCESS");
                res.setHeader('Set-Cookie', [`wallet_token=${result.wallet_token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`, `email=${loginData.email}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`, `userId=${result.id}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`]);
                res.writeHead(200, {'Content-Type': 'application/json'});
                res.end(JSON.stringify({operation: "success"}));
            }
        }

        let lastAttempt = await client.getLastLoginAttempt(loginData.email);
        //more than 5 attempts access is locked for 30min
        if (loginAttempts >= 5 && lastAttempt > new Date().getTime() - 30 * 60 * 1000) {
            await client.loginEvent(req.userId, "FAIL", `Exceeded number of attempts`);
            logger.debug(`Exceeded number of attempts: ${JSON.stringify(loginData)}`);
            res.writeHead(403, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({
                error: "Exceeded number of attempts",
                details: {
                    lockTime: lastAttempt + 30 * 60 * 1000 - new Date().getTime()
                }
            }));
            return;
        }

        //reset attempts as 30min passed
        if (loginAttempts >= 5 && lastAttempt <= new Date().getTime() - 30 * 60 * 1000) {
            await client.resetLoginAttempts(loginData.email);
        }

    } catch (e) {
        await client.loginEvent(req.userId, "FAIL", "");
        logger.debug(`${req.userId} login failed : ${e.message}`);
        res.writeHead(500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: "Operation failed"}));
    }
}

const walletLogout = async (req, res) => {
    let cookies = getCookies(req);
    let clearedCookies = [];
    for(let cookie of Object.keys(cookies)){
        clearedCookies.push(`${cookie}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`);
    }
    res.setHeader('Set-Cookie', clearedCookies);
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({operation: "success"}));
}

const getAccount = async (req, res) => {
    try {
        let {email} = req.params;
        email = decodeURIComponent(email);
        validateEmail(email);
        const enclaveInstance = await getEnclaveInstance();
        let user = await $$.promisify(enclaveInstance.getRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, email);
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify(user));
    } catch (e) {
        logger.debug(e.message);
        res.writeHead(500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: e.message}));
    }

}
const updateAccount = async (req, res) => {
    try {
        let {email} = req.params;
        let data;
        try {
            data = JSON.parse(req.body);
        }catch (e) {
            res.writeHead(415, {'Content-Type': 'application/json'});
            logger.debug(e.message);
            res.end(JSON.stringify({error: "Wrong data"}));
            return;
        }

        email = decodeURIComponent(email);
        validateEmail(email);
        const enclaveInstance = await getEnclaveInstance();
        await $$.promisify(enclaveInstance.updateRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, email, data);
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({operation: "success"}));
    } catch (e) {
        logger.debug(e.message);
        res.writeHead(500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: e.message}));
    }
}
module.exports = {
    generateAuthCode,
    walletLogin,
    walletLogout,
    accountExists,
    getAccount,
    updateAccount
}
