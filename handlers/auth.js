const logger = $$.getLogger("apis", "auth");
const process = require("process");
const openDSU = require('opendsu');
const system = openDSU.loadApi("system");
const baseURL = system.getBaseURL();
const resolver = openDSU.loadAPI("resolver");
const utils = require("../utils/apiUtils");
const constants = require("../utils/constants");
async function initAPIClient(req, pluginName){
    return await require("opendsu").loadAPI("serverless").createServerlessAPIClient(req.userId || "*", baseURL,  process.env.SERVERLESS_ID, pluginName, "",{sessionId: req.sessionId});
}
const userExists = async function (req, res) {
    let response;
    try {
        let {email} = req.params;
        email = decodeURIComponent(email);
        utils.validateEmail(email);
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        response = await client.userExists(email);
    } catch (err) {
        logger.debug(err.message);
        res.writeHead(500, {'Content-Type': 'application/json'});
        return res.end(JSON.stringify({error: err.message}));
    }
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({account_exists: response.userExists}));
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
    let client = await initAPIClient(req, constants.USER_PLUGIN);

    try {
        let {email, name, referrerId} = authData;
        utils.validateEmail(email);
        let result = await client.getUserValidationEmailCode(email, name, referrerId);
        if (result.status === "success") {
            if(result.walletKey){
                const versionlessSSI = utils.getVersionlessSSI(email, result.walletKey);
                await $$.promisify(resolver.createDSUForExistingSSI)(versionlessSSI);
                let dsu = await $$.promisify(resolver.loadDSU)(versionlessSSI);
            }
            let responseMessage = {result: "success"};
            if (req.headers.origin === "http://localhost:8080") {
                responseMessage.code = result.code;
            } else {
                let emailClient = await initAPIClient(req, constants.EMAIL_PLUGIN);
                let subject = "Your authentication code";
                let text = `Your authentication code is: ${result.code}`;
                let html = `Your authentication code is: <strong>${result.code}</strong>`;
                await emailClient.sendEmail(email, process.env.SENDGRID_SENDER_EMAIL, subject, text, html);
            }
            res.writeHead(200, {'Content-Type': 'application/json'});
            return res.end(JSON.stringify(responseMessage));
        }
        //await client.loginEvent(req.userId, "FAIL", `Exceeded number of attempts`);
        res.writeHead(403, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({
            error: result.reason,
            details: {
                lockTime: result.lockTime
            }
        }));
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
    let client = await initAPIClient(req, constants.USER_PLUGIN);
    try {
        utils.validateEmail(loginData.email);
        let result = await client.authorizeUser(loginData.email, loginData.code);
        if(result.status === "success"){
            //await client.loginEvent(result.userId, "SUCCESS");
            let cookies = utils.createAuthCookies(result.userId,  result.email, result.walletKey, result.sessionId);
            res.setHeader('Set-Cookie', cookies);
            res.writeHead(200, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({operation: "success"}));
        } else {
            //await client.loginEvent(req.userId, "FAIL", result.message);
            res.writeHead(401, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({error: result.reason}));
        }
    } catch (e) {
        //await client.loginEvent(req.userId, "FAIL", "");
        logger.debug(`${req.userId} login failed : ${e.message}`);
        res.writeHead(500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: "Operation failed"}));
    }
}

const walletLogout = async (req, res) => {
    try {
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        let cookies = utils.getCookies(req);
        await client.logout(cookies.sessionId);
        let clearedCookies = [];
        for(let cookie of Object.keys(cookies)){
            clearedCookies.push(`${cookie}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`);
        }
        res.setHeader('Set-Cookie', clearedCookies);
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({operation: "success"}));
    } catch (e) {
        res.writeHead(500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: e.message}));
    }
}

const getUserInfo = async (req, res) => {
    try {
        let {email} = req.query;
        if(!email){
            email = req.email;
        }
        email = decodeURIComponent(email);
        utils.validateEmail(email);
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        let result = await client.getUserInfo(email);
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify(result.userInfo));
    } catch (e) {
        logger.debug(e.message);
        res.writeHead(500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: e.message}));
    }

}

const setUserInfo = async (req, res) => {
    try {
        let {email} = req.query;
        if(!email){
            email = req.email;
        }
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
        utils.validateEmail(email);
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        await client.setUserInfo(email, data);
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
    userExists,
    getUserInfo,
    setUserInfo
}
