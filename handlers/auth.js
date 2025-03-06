const logger = $$.getLogger("apis", "auth");
const path = require("path");
const fs = require("fs");
const process = require("process");
const sgMail = require("@sendgrid/mail");
const openDSU = require('opendsu');
const resolver = openDSU.loadAPI("resolver");
const crypto = openDSU.loadAPI("crypto");
const lockApi = openDSU.loadApi("lock");
const AUTH_CODES_TABLE = "auth_codes_table";
const {getVersionlessSSI, getEnclaveInstance, generateRandomCode, validateEmail, interfaceDefinition} = require("./../apiutils/utils");


sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const senderEmail = process.env.SENDGRID_SENDER_EMAIL;     // Change to your verified sender from sendgrid

const accountExists = async function (req, res) {
    let response;
    try {
        let {email} = req.params;
        email = decodeURIComponent(email);
        validateEmail(email);
        const enclaveInstance = await getEnclaveInstance();
        response = await $$.promisify(enclaveInstance.getRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, email);
    } catch (err) {
        logger.debug(err.message);
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
    const enclaveInstance = await getEnclaveInstance();
    try {
        let {email, refererId} = authData;
        validateEmail(email);
        let code = generateRandomCode(5)

        let result = await $$.promisify(enclaveInstance.getRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, email);
        if (!result) {

            if (refererId) {
                const {getFullName} = require("/creditManager/util/CoreUtil");
                refererId = getFullName(refererId, "U");
            }

            let user = await req.servelessClients[req.userId].addAccount(email, email.split("@")[0], refererId);

            result = {
                code: code,
                wallet_token: crypto.sha256(crypto.generateRandom(32)),
                attempts: 0,
                id: user.id,
                invitations: []
            };
            const versionlessSSI = getVersionlessSSI(email, result.wallet_token);
            await $$.promisify(resolver.createDSUForExistingSSI)(versionlessSSI);
            let dsu = await $$.promisify(resolver.loadDSU)(versionlessSSI);

            /*
            let batchId = await dsu.startOrAttachBatchAsync();
            await $$.promisify(dsu.writeFile)(`/walletData.json`, JSON.stringify({
                invitations: []
            }));
            await dsu.commitBatchAsync(batchId);
            */
            await $$.promisify(enclaveInstance.insertRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, email, result);
            if (refererId) {
                let refererResult = await $$.promisify(enclaveInstance.filter)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, [`id == "${refererId}"`]);
                refererResult[0].invitations.push(user.id);
                await $$.promisify(enclaveInstance.updateRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, refererResult[0].pk, refererResult[0]);

            }

        } else {
            if (result.attempts >= 5 && result.lastAttempt > new Date().getTime() - 30 * 60 * 1000) {
                /*await fameLogs.systemLog({
                    action: actions.ERROR,
                    details: `Exceeded number of attempts in generateAuthCode: ${JSON.stringify(authData)}`
                });
                await fameLogs.userLog(result.id, {
                    action: actions.ERROR, details: `Exceeded number of attempts`
                });*/
                await req.servelessClients[req.userId].loginEvent(req.userId, "FAIL", `Exceeded number of attempts`);
                logger.debug(`Exceeded number of attempts in generateAuthCode: ${JSON.stringify(authData)}`);
                res.writeHead(403, {'Content-Type': 'application/json'});
                res.end(JSON.stringify({
                    error: "Exceeded number of attempts",
                    details: {
                        lockTime: result.lastAttempt + 30 * 60 * 1000 - new Date().getTime()
                    }
                }));
                return;
            }
            if (result.attempts >= 5 && result.lastAttempt <= new Date().getTime() - 30 * 60 * 1000) {
                result.attempts = 0;
                await $$.promisify(enclaveInstance.updateRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, email, result);
            }
            result.code = code;
            await $$.promisify(enclaveInstance.updateRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, email, result);
        }

        let resultObj = {"result": "success"};
        if (req.headers.origin === "http://localhost:8080") {
            let codesPath = path.resolve(path.join(req.externalVolumePath, "codes.txt"));
            if (!fs.existsSync(path.dirname(codesPath))) {
                fs.mkdirSync(path.dirname(codesPath), {recursive: true});
            }
            await fs.promises.writeFile(codesPath, code);
            resultObj.code = code
        } else {
            const msg = {
                "to": email,
                "from": senderEmail,
                "subject": "Your Hatefinity authentication code",
                "text": `Your authentication code is: ${code}`,
                "html": `Your authentication code is: <strong>${code}</strong>`,
            }
            sgMail.send(msg).then(() => {
                logger.debug('Email sent successfully');
            }).catch((error) => {
                logger.debug(error.message);
            });
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
    const enclaveInstance = await getEnclaveInstance();
    try {
        validateEmail(loginData.email);
        let result = await $$.promisify(enclaveInstance.getRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, loginData.email);

        if (!result || (result.attempts < 5 && result.code !== loginData.code)) {
            result.attempts = parseInt(result.attempts) + 1;
            result.lastAttempt = new Date().getTime();
            await $$.promisify(enclaveInstance.updateRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, loginData.email, result);

            logger.debug(`${req.userId} Wrong login data: ${JSON.stringify(loginData)}`);
/*            await fameLogs.systemLog({
                action: actions.ERROR, details: `Wrong login data: ${JSON.stringify(loginData)}`
            });*/
            if (result) {
/*                await fameLogs.userLog(result.id, {
                    action: actions.ERROR, details: `Wrong login data`
                });*/
                logger.debug(`${req.userId} Wrong login data`);
            }
            res.writeHead(401, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({error: "Invalid credentials"}));
            return;
        }

        //more than 5 attempts access is locked for 30min
        if (result.attempts >= 5 && result.lastAttempt > new Date().getTime() - 30 * 60 * 1000) {

          /*  await fameLogs.systemLog({
                action: actions.ERROR, details: `Exceeded number of attempts: ${JSON.stringify(loginData)}`
            });
            await fameLogs.userLog(result.id, {
                action: actions.ERROR, details: `Exceeded number of attempts`
            });*/
            await req.servelessClients[req.userId].loginEvent(req.userId, "FAIL", `Exceeded number of attempts`);

            logger.debug(`Exceeded number of attempts: ${JSON.stringify(loginData)}`);
            res.writeHead(403, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({
                error: "Exceeded number of attempts",
                details: {
                    lockTime: result.lastAttempt + 30 * 60 * 1000 - new Date().getTime()
                }
            }));
            return;
        }

        //reset attempts as 30min passed
        if (result.attempts >= 5 && result.lastAttempt <= new Date().getTime() - 30 * 60 * 1000) {
            result.attempts = 0;
            await $$.promisify(enclaveInstance.updateRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, loginData.email, result);
        }

        if (result.attempts < 5 && result.code === loginData.code) {
            if (result.__timestamp < new Date().getTime() - 15 * 60 * 1000) {
               /* await fameLogs.systemLog({
                    action: actions.ERROR, details: `Code is expired: ${JSON.stringify(loginData)}`
                });
                await fameLogs.userLog(result.id, {
                    action: actions.ERROR, details: `Expired code`
                });*/
                await req.servelessClients[req.userId].loginEvent(req.userId, "FAIL", `Expired code`);

                logger.debug(`Code is expired: ${JSON.stringify(loginData)}`);
                res.writeHead(440, {'Content-Type': 'application/json'});
                res.end(JSON.stringify({error: "Invalid credentials"}));
                return;
            }

            const versionlessSSI = getVersionlessSSI(result.pk, result.wallet_token);

            let dsu = await $$.promisify(resolver.loadDSU)(versionlessSSI);
            /* let apiKey;
             try {
                 apiKey = await $$.promisify(dsu.readFile, dsu)(OUTFINITY_FAME_LOCK_KEY_ID);
             } catch (e) {
                 logger.debug(e);
             }
             if (!apiKey) {
                 throw new Error("API key not found");
             }
 */
            if (!dsu) {
                throw new Error("DSU not found");
            }
            /*
                HttpOnly - Prevents JavaScript access to the cookie
                Secure - Ensures the cookie is sent over HTTPS only
                SameSite=Strict - Prevents CSRF attacks
                Max-Age=${24 * 60 * 60 * 1000} - 1 day in milliseconds
             */
            if (result.attempts > 0) {
                result.attempts = 0;
                await $$.promisify(enclaveInstance.updateRecord)($$.SYSTEM_IDENTIFIER, AUTH_CODES_TABLE, loginData.email, result);
            }
            //   await fameLogs.systemLog({action: actions.USER_LOGIN, details: new Date().toISOString()});

            if (!req.servelessClients[result.id]) {
                const client = require("opendsu").loadAPI("serverless").createServerlessAPIClient(result.id, req.servelessServerUrl, interfaceDefinition);
                req.servelessClients[result.id] = client;
            }
            await req.servelessClients[result.id].loginEvent(result.id, "SUCCESS");
            res.setHeader('Set-Cookie', [`wallet_token=${result.wallet_token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`, `email=${loginData.email}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`, `userId=${result.id}; HttpOnly; Secure; SameSite=Strict; Max-Age=${24 * 60 * 60}; Path=/`]);
            res.writeHead(200, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({operation: "success"}));
        } else {
            throw new Error(`Unexpected error: ${JSON.stringify(loginData)}`);
        }

    } catch (e) {
        /* await fameLogs.systemLog({action: actions.ERROR, details: e.message});*/
       // await req.servelessClients[req.userId].loginEvent(req.userId, "FAIL", "");
        logger.debug(`${req.userId} login failed : ${e.message}`);
        res.writeHead(500, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: "Operation failed"}));
    }
}

const walletLogout = async (req, res) => {
    res.setHeader('Set-Cookie', [
        'wallet_token=; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
        'email=; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
    ]);
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
