// Gatekeeper/handlers/auth.js
const logger = $$.getLogger("apis", "auth");
const process = require("process");
const openDSU = require('opendsu');
const system = openDSU.loadApi("system");
const baseURL = system.getBaseURL();
const resolver = openDSU.loadAPI("resolver");
const utils = require("../utils/apiUtils");
const constants = require("../utils/constants");
const authStrategyFactory = require('../strategies/AuthStrategyFactory');
const { AUTH_TYPES, STATUS } = require('../constants/authConstants');

async function initAPIClient(req, pluginName) {
    const userId = req.userId || '*';
    const sessionId = req.sessionId || undefined;
    return await require("opendsu").loadAPI("serverless").createServerlessAPIClient(
        userId, baseURL, process.env.SERVERLESS_ID, pluginName, "", { sessionId: sessionId }
    );
}

let factoryInitialized = false;
async function ensureFactoryInitialized(req) {
    if (!factoryInitialized) {
        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const emailClient = await initAPIClient(req, constants.EMAIL_PLUGIN);
        authStrategyFactory.init(userLoginClient, emailClient);
        factoryInitialized = true;
    }
}

const userExists = async function (req, res) {
    let response;
    try {
        let { email } = req.params;
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        await ensureFactoryInitialized(req);

        const strategy = await authStrategyFactory.getStrategyForUser(email);
        response = await strategy.checkUserExists(email);

    } catch (err) {
        logger.error(`Error in userExists for ${req.params.email}: ${err.message}`, err.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ account_exists: response.userExists, ...response }));
}

const generateAuthCode = async function (req, res) {
    let authData = req.body;
    let parsedData;
    try {
        parsedData = JSON.parse(authData);
        utils.validateEmail(parsedData.email);
        if (parsedData.activeAuthType === AUTH_TYPES.PASSKEY && !parsedData.registrationData) {
            throw new Error("Missing registrationData for passkey signup.");
        }
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for generateAuthCode: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    await ensureFactoryInitialized(req);

    try {
        const { email, authType } = parsedData;

        const strategy = authStrategyFactory.getStrategy(authType);

        const result = await strategy.generateAuthData({
            ...parsedData,
            origin: req.headers.origin
        });

        if (result.walletKey) {
            const versionlessSSI = utils.getVersionlessSSI(email, result.walletKey);
            await $$.promisify(resolver.createDSUForExistingSSI)(versionlessSSI);
            logger.info(`DSU created for new ${authType} user ${email}`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(result));

    } catch (e) {
        logger.error(`Error during generateAuthCode for ${parsedData.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}


const walletLogin = async (req, res) => {
    let loginData = req.body;
    let parsedData;
    try {
        parsedData = JSON.parse(loginData);
        utils.validateEmail(parsedData.email);

        if (!parsedData.loginMethod ||
            ![AUTH_TYPES.PASSKEY, AUTH_TYPES.EMAIL, AUTH_TYPES.TOTP].includes(parsedData.loginMethod)) {
            throw new Error("Missing or invalid 'loginMethod'");
        }

        switch (parsedData.loginMethod) {
            case AUTH_TYPES.PASSKEY:
                if (typeof parsedData.assertion !== 'object' || !parsedData.assertion.id || !parsedData.challengeKey) {
                    throw new Error("Invalid or incomplete passkey assertion data or missing challengeKey.");
                }
                break;
            case AUTH_TYPES.EMAIL:
                if (typeof parsedData.code !== 'string') {
                    throw new Error("Invalid or missing email code.");
                }
                parsedData.code = parsedData.code.trim();
                break;
            case AUTH_TYPES.TOTP:
                if (typeof parsedData.token !== 'string' || !/^[0-9]{6}$/.test(parsedData.token)) {
                    throw new Error("Invalid or missing TOTP token.");
                }
                break;
        }

    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid login data: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid login data: ${e.message}` }));
    }

    await ensureFactoryInitialized(req);

    try {
        const { email, loginMethod } = parsedData;

        const strategyType = loginMethod === AUTH_TYPES.EMAIL ? AUTH_TYPES.EMAIL : loginMethod;

        const strategy = authStrategyFactory.getStrategy(strategyType);

        const result = await strategy.login(parsedData);

        if (result.success) {
            let cookies = utils.createAuthCookies(result.userId, result.email, result.walletKey, result.sessionId);
            res.setHeader('Set-Cookie', cookies);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success" }));
            logger.info(`User ${email} logged in successfully (${loginMethod}).`);
        } else {
            const statusCode = (result.error === "exceeded number of attempts") ? 403 : 401;
            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                error: result.error,
                details: { lockTime: result.lockTime }
            }));
            logger.warn(`User ${email} login failed (${loginMethod}): ${result.error}`);
        }
    } catch (e) {
        logger.error(`Error during walletLogin for ${parsedData.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const registerNewPasskey = async (req, res) => {
    if (!req.userId || !req.email) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Authentication required." }));
    }

    let registrationData;
    try {
        registrationData = JSON.parse(req.body);
        if (!registrationData || !registrationData.id || !registrationData.rawId || !registrationData.type || !registrationData.response ||
            !registrationData.response.clientDataJSON || !registrationData.response.attestationObject) {
            throw new Error("Invalid passkey registration data structure.");
        }
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for registerNewPasskey: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    await ensureFactoryInitialized(req);

    let email = decodeURIComponent(req.email);
    try {
        const passkeyStrategy = authStrategyFactory.getStrategy(AUTH_TYPES.PASSKEY);

        let result = await passkeyStrategy.registerNewPasskey(email, registrationData);

        if (result.status) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success", credentialId: result.credentialId }));
            logger.info(`Successfully registered new passkey for user ${email}`);
        } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: result.error || "Failed to register new passkey." }));
            logger.warn(`Failed to register new passkey for user ${email}: ${result.error}`);
        }
    } catch (e) {
        logger.error(`Error during registerNewPasskey for ${email}: ${e.message}`, e.stack);
        const statusCode = e.message.includes("already registered") ? 409 : 500;
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}


const walletLogout = async (req, res) => {
    if (!req.sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Session information missing." }));
    }

    try {
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        await client.logout(req.sessionId);

        let cookies = utils.getCookies(req);
        let clearedCookies = [];
        for (let cookie of Object.keys(cookies)) {
            clearedCookies.push(`${cookie}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`);
        }
        res.setHeader('Set-Cookie', clearedCookies);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ operation: "success" }));
        logger.info(`User ${req.email || req.userId || 'Unknown'} logged out.`);
    } catch (e) {
        logger.error(`Error during walletLogout: ${e.message}`, e.stack);
        let cookies = utils.getCookies(req);
        let clearedCookies = [];
        for (let cookie of Object.keys(cookies)) {
            clearedCookies.push(`${cookie}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`);
        }
        res.setHeader('Set-Cookie', clearedCookies);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Logout operation failed: ${e.message}` }));
    }
}

const getUserInfo = async (req, res) => {
    try {
        let { email } = req.query;
        if (!email) {
            email = req.email;
        }
        email = decodeURIComponent(email);
        utils.validateEmail(email);
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        let result = await client.getUserInfo(email);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result.userInfo));
    } catch (e) {
        logger.debug(e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
    }
}

const setUserInfo = async (req, res) => {
    try {
        let { email } = req.query;
        if (!email) {
            email = req.email;
        }

        let data;
        try {
            data = JSON.parse(req.body);
        } catch (e) {
            res.writeHead(415, { 'Content-Type': 'application/json' });
            logger.debug(e.message);
            res.end(JSON.stringify({ error: "Wrong data" }));
            return;
        }

        email = decodeURIComponent(email);
        utils.validateEmail(email);
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        await client.setUserInfo(email, data);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ operation: "success" }));
    } catch (e) {
        logger.debug(e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
    }
}

const registerTotp = async (req, res) => {
    if (!req.userId || !req.email) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Authentication required." }));
    }

    try {
        await ensureFactoryInitialized(req);

        const email = decodeURIComponent(req.email);

        const totpStrategy = authStrategyFactory.getStrategy("totp");

        const result = await totpStrategy.setupTotp(email);

        if (result.status) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: STATUS.SUCCESS,
                uri: result.uri,
                secret: result.secret
            }));
            logger.info(`TOTP setup initiated for user ${email}`);
        } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: STATUS.FAILED,
                error: result.error || "Failed to set up TOTP"
            }));
        }
    } catch (e) {
        logger.error(`Error during TOTP registration for ${req.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
};

const verifyTotp = async (req, res) => {
    let verifyData;
    try {
        verifyData = JSON.parse(req.body);

        const { token, email, enableTotp } = verifyData;

        if (!token || !/^[0-9]{6}$/.test(token)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: "Please enter a valid 6-digit code." }));
        }

        let userEmail = email;

        if (!userEmail && enableTotp === true) {
            if (!req.email) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: "Authentication required." }));
            }
            userEmail = decodeURIComponent(req.email);
        }

        if (!userEmail) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: "Email is required." }));
        }

        await ensureFactoryInitialized(req);

        const totpStrategy = authStrategyFactory.getStrategy(AUTH_TYPES.TOTP);

        if (enableTotp === true) {
            const result = await totpStrategy.verifyAndEnableTotp(userEmail, token);

            if (result.success) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    status: STATUS.SUCCESS,
                    message: "TOTP enabled successfully"
                }));
                logger.info(`TOTP enabled for user ${userEmail}`);
            } else {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    status: STATUS.FAILED,
                    error: result.error || "Invalid verification code"
                }));
            }
        } else {
            const loginResult = await totpStrategy.login({
                email: userEmail,
                token: token
            });

            if (loginResult.success) {
                let cookies = utils.createAuthCookies(
                    loginResult.userId,
                    loginResult.email,
                    loginResult.walletKey,
                    loginResult.sessionId
                );
                res.setHeader('Set-Cookie', cookies);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ operation: "success" }));
                logger.info(`User ${userEmail} logged in successfully using TOTP.`);
            } else {
                const statusCode = (loginResult.error === "exceeded number of attempts") ? 403 : 401;
                res.writeHead(statusCode, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    error: loginResult.error,
                    details: { lockTime: loginResult.lockTime }
                }));
                logger.warn(`User ${userEmail} TOTP login failed: ${loginResult.error}`);
            }
        }
    } catch (e) {
        logger.error(`Error during TOTP verification: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
};

const getAuthTypes = async function (req, res) {
    try {
        let { email } = req.params;
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        await ensureFactoryInitialized(req);

        let userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);

        const userInfoResult = await userLoginClient.getUserInfo(email);

        if (userInfoResult.status !== AUTH_TYPES.STATUS.SUCCESS) {
            throw new Error(userInfoResult.reason || "Failed to get user information");
        }

        const userInfo = userInfoResult.userInfo;
        const authMethods = [];

        if (userInfo.authTypes && userInfo.authTypes.length > 0) {
            userInfo.authTypes.forEach(authType => {
                if (authType !== AUTH_TYPES.PASSKEY) {
                    authMethods.push({
                        type: authType,
                        createdAt: userInfo.createdAt || null
                    });
                }
            });
        }

        if (userInfo.passkeyCredentials && userInfo.passkeyCredentials.length > 0) {
            userInfo.passkeyCredentials.forEach(passkey => {
                authMethods.push({
                    type: AUTH_TYPES.PASSKEY,
                    id: passkey.id,
                    name: passkey.name,
                    createdAt: passkey.createdAt,
                    transports: passkey.transports
                });
            });
        }

        if (userInfo.totpEnabled || userInfo.totpPendingSetup) {
            const totpMethod = authMethods.find(method => method.type === AUTH_TYPES.TOTP);
            if (totpMethod) {
                totpMethod.enabled = userInfo.totpEnabled;
                totpMethod.setupPending = !!userInfo.totpPendingSetup;
            } else {
                authMethods.push({
                    type: AUTH_TYPES.TOTP,
                    enabled: userInfo.totpEnabled,
                    setupPending: !!userInfo.totpPendingSetup
                });
            }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: STATUS.SUCCESS,
            userExists: true,
            authMethods: authMethods
        }));

    } catch (err) {
        logger.error(`Error in getAuthTypes for ${req.params?.email || 'unknown'}: ${err.message}`, err.stack);

        if (err.message && err.message.includes("user not exists")) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
                status: STATUS.SUCCESS,
                userExists: false,
                authMethods: []
            }));
        }

        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
    }
}

module.exports = {
    generateAuthCode,
    walletLogin,
    walletLogout,
    userExists,
    getUserInfo,
    setUserInfo,
    registerNewPasskey,
    registerTotp,
    verifyTotp,
    getAuthTypes
}