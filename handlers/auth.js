const logger = $$.getLogger("apis", "auth");
const process = require("process");
const openDSU = require('opendsu');
const system = openDSU.loadApi("system");
const baseURL = system.getBaseURL();
const utils = require("../utils/apiUtils");
const constants = require("../utils/constants");
const { STATUS, ERROR_REASONS } = require('../constants/authConstants');

// Shared challenge cache for passkey registration
const challengeCache = new Map();

async function initAPIClient(req, pluginName) {
    const userId = req.userId;
    const sessionId = req.sessionId || undefined;
    return await require("opendsu").loadAPI("serverless").createServerlessAPIClient(
        userId, baseURL, process.env.SERVERLESS_ID, pluginName, "", { sessionId: sessionId, email: req.email }
    );
}

// Removed userExists function - now using getAuthInfo for authenticated access and getPublicAuthInfo for public access

const sendCodeByEmail = async function (req, res) {
    let authData = req.body;
    let parsedData;
    let email;
    try {
        if (authData) {
            parsedData = JSON.parse(authData);
        }
        email = parsedData.email;
        utils.validateEmail(email);
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for sendCodeByEmail: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    req.email = email;

    try {
        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await userLoginClient.requestEmailCode(email, parsedData?.name, parsedData?.referrerId);

        if (result.status === STATUS.SUCCESS) {
            let responseMessage = { status: STATUS.SUCCESS };

            // Include code in response only for development or localhost
            if (process.env.NODE_ENV === 'development' || req.headers.origin === "http://localhost:8080") {
                responseMessage.code = result.code;
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify(responseMessage));
        } else {
            throw new Error(result.reason || "Failed to generate email code");
        }
    } catch (e) {
        logger.error(`Error during sendCodeByEmail for ${email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const loginWithEmailCode = async function (req, res) {
    let email;
    let authData = req.body;
    let parsedData;
    try {
        parsedData = JSON.parse(authData);
        email = parsedData.email;
        utils.validateEmail(email);
        if (typeof parsedData.code !== 'string' || !parsedData.code.trim()) {
            throw new Error("Missing or invalid email code.");
        }
        parsedData.code = parsedData.code.trim();
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for loginWithEmailCode: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    req.email = email;

    try {
        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await userLoginClient.loginWithEmailCode(email, parsedData.code);

        if (result.status === STATUS.SUCCESS) {
            let cookies = utils.createAuthCookies(result.userId, result.email, result.walletKey, result.sessionId);
            res.setHeader('Set-Cookie', cookies);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success" }));
            logger.info(`User ${email} logged in successfully (Email Code).`);
        } else {
            const statusCode = (result.reason === "exceeded number of attempts") ? 403 : 401;
            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                error: result.reason,
                details: { lockTime: result.lockTime }
            }));
            logger.warn(`User ${email} email code login failed: ${result.reason}`);
        }
    } catch (e) {
        logger.error(`Error during loginWithEmailCode for ${email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const generatePasskeySetupOptions = async (req, res) => {
    if (!req.userId || !req.email) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Authentication required." }));
    }

    const email = decodeURIComponent(req.email);

    try {
        // Generate registration options on server for passkey setup
        const crypto = require("crypto");
        const challenge = crypto.randomBytes(32);
        const challengeKey = `passkey_setup_challenge_${email}_${Date.now()}`;

        // Store challenge temporarily (5 minutes)
        challengeCache.set(challengeKey, {
            challenge: challenge.toString('base64url'),
            email: email,
            timestamp: Date.now(),
            type: 'setup'
        });

        // Clean up expired challenges
        setTimeout(() => challengeCache.delete(challengeKey), 5 * 60 * 1000);

        const publicKeyCredentialCreationOptions = {
            challenge: challenge.toString('base64url'),
            rp: {
                name: process.env.RP_NAME || "Outfinity Gift",
                id: process.env.RP_ID,
            },
            user: {
                id: Buffer.from(email).toString('base64url'),
                name: email,
                displayName: email,
            },
            pubKeyCredParams: [
                { type: 'public-key', alg: -7 }, // ES256
                { type: 'public-key', alg: -257 }, // RS256
            ],
            authenticatorSelection: {
                requireResidentKey: false,
                userVerification: 'required',
            },
            timeout: 60000,
            attestation: 'direct'
        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: "success",
            publicKeyCredentialCreationOptions: JSON.stringify(publicKeyCredentialCreationOptions),
            challengeKey: challengeKey
        }));

    } catch (e) {
        logger.error(`Error during generatePasskeySetupOptions for ${email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const loginWithPasskey = async function (req, res) {
    let loginData = req.body;
    let parsedData;
    try {
        parsedData = JSON.parse(loginData);
        utils.validateEmail(parsedData.email);

        if (typeof parsedData.assertion !== 'object' || !parsedData.assertion.id || !parsedData.challengeKey) {
            throw new Error("Invalid or incomplete passkey assertion data or missing challengeKey.");
        }
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for loginWithPasskey: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    req.email = parsedData.email;

    try {
        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await userLoginClient.loginWithPasskey(parsedData.email, parsedData.assertion, parsedData.challengeKey);

        if (result.status === STATUS.SUCCESS) {
            let cookies = utils.createAuthCookies(result.userId, result.email, result.walletKey, result.sessionId);
            res.setHeader('Set-Cookie', cookies);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success" }));
            logger.info(`User ${parsedData.email} logged in successfully (Passkey).`);
        } else {
            const statusCode = (result.reason === "exceeded number of attempts") ? 403 : 401;
            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                error: result.reason,
                details: { lockTime: result.lockTime }
            }));
            logger.warn(`User ${parsedData.email} passkey login failed: ${result.reason}`);
        }
    } catch (e) {
        logger.error(`Error during loginWithPasskey for ${parsedData.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const loginWithTotp = async function (req, res) {
    let loginData = req.body;
    let parsedData;
    try {
        parsedData = JSON.parse(loginData);
        utils.validateEmail(parsedData.email);

        if (typeof parsedData.token !== 'string' || !/^[0-9]{6}$/.test(parsedData.token)) {
            throw new Error("Invalid or missing TOTP token.");
        }
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for loginWithTotp: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    req.email = parsedData.email;

    try {
        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await userLoginClient.loginWithTotp(parsedData.email, parsedData.token);

        if (result.status === STATUS.SUCCESS) {
            let cookies = utils.createAuthCookies(result.userId, result.email, result.walletKey, result.sessionId);
            res.setHeader('Set-Cookie', cookies);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success" }));
            logger.info(`User ${parsedData.email} logged in successfully (TOTP).`);
        } else {
            const statusCode = (result.reason === "exceeded number of attempts") ? 403 : 401;
            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                error: result.reason,
                details: { lockTime: result.lockTime }
            }));
            logger.warn(`User ${parsedData.email} TOTP login failed: ${result.reason}`);
        }
    } catch (e) {
        logger.error(`Error during loginWithTotp for ${parsedData.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

// Removed walletLogin - we now have dedicated login endpoints for each auth type

const logout = async (req, res) => {
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
        logger.error(`Error during logout: ${e.message}`, e.stack);
        // Clear cookies even on error
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

const addPasskey = async (req, res) => {
    if (!req.userId || !req.email) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Authentication required." }));
    }

    let requestData;
    try {
        requestData = JSON.parse(req.body);
        if (!requestData.registrationData || !requestData.challengeKey) {
            throw new Error("Missing registrationData or challengeKey.");
        }

        const { registrationData } = requestData;
        if (!registrationData.id || !registrationData.rawId || !registrationData.type || !registrationData.response ||
            !registrationData.response.clientDataJSON || !registrationData.response.attestationObject) {
            throw new Error("Invalid passkey registration data structure.");
        }
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for addPasskey: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    let email = decodeURIComponent(req.email);
    try {
        // Validate challenge
        const challengeData = challengeCache.get(requestData.challengeKey);
        if (!challengeData) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: "Invalid or expired registration challenge." }));
        }

        if (challengeData.email !== email || challengeData.type !== 'setup') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: "Challenge validation failed." }));
        }

        // Clean up used challenge
        challengeCache.delete(requestData.challengeKey);

        const client = await initAPIClient(req, constants.USER_PLUGIN);
        let result = await client.addPasskey(email, requestData.registrationData);

        if (result.status === STATUS.SUCCESS) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success", credentialId: result.credentialId }));
            logger.info(`Successfully registered new passkey for user ${email}`);
        } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: result.reason || "Failed to register new passkey." }));
            logger.warn(`Failed to register new passkey for user ${email}: ${result.reason}`);
        }
    } catch (e) {
        logger.error(`Error during addPasskey for ${email}: ${e.message}`, e.stack);
        const statusCode = e.message.includes("already registered") ? 409 : 500;
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const deletePasskey = async function (req, res) {
    try {
        let email = req.params.email;
        if (!email) {
            if (!req.email) {
                res.statusCode = 400;
                return res.end(JSON.stringify({
                    status: STATUS.FAILED,
                    message: "No email provided"
                }));
            }
            email = req.email;
        }
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        if (!req.params.credentialId) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
                status: STATUS.FAILED,
                message: "No credential ID provided"
            }));
        }
        const credentialId = decodeURIComponent(req.params.credentialId);
        const api = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await api.deletePasskey(email, credentialId);

        if (result.status !== STATUS.SUCCESS) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
                status: STATUS.FAILED,
                message: result.reason || "Failed to delete passkey"
            }));
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: STATUS.SUCCESS,
            message: result.message || "Passkey successfully deleted"
        }));
    } catch (error) {
        console.error("Error in deletePasskey handler:", error);
        res.statusCode = 500;
        return res.end(JSON.stringify({
            status: STATUS.FAILED,
            message: "An error occurred while deleting the passkey"
        }));
    }
}

const setupTotp = async (req, res) => {
    if (!req.userId || !req.email) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Authentication required." }));
    }

    try {
        const email = decodeURIComponent(req.email);
        const client = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await client.setupTotp(email);

        if (result.status === STATUS.SUCCESS) {
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
                error: result.reason || "Failed to set up TOTP"
            }));
        }
    } catch (e) {
        logger.error(`Error during TOTP setup for ${req.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const enableTotp = async (req, res) => {
    let enableData;
    try {
        enableData = JSON.parse(req.body);

        const { token, email } = enableData;

        if (!token || !/^[0-9]{6}$/.test(token)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: "Please enter a valid 6-digit code." }));
        }

        let userEmail = email;

        if (!userEmail) {
            if (!req.email) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: "Authentication required." }));
            }
            userEmail = decodeURIComponent(req.email);
        }

        const client = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await client.confirmTotpSetup(userEmail, token);

        if (result.status === STATUS.SUCCESS) {
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
                error: result.reason || "Invalid verification code"
            }));
        }
    } catch (e) {
        logger.error(`Error during TOTP enablement: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

const deleteTotp = async function (req, res) {
    try {
        let email = req.params.email;
        if (!email) {
            if (!req.email) {
                res.statusCode = 401;
                return res.end(JSON.stringify({
                    status: STATUS.FAILED,
                    message: "You must be logged in to delete TOTP authentication"
                }));
            }
            email = req.email;
        }
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        const api = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await api.deleteTotp(email);

        if (result.status !== STATUS.SUCCESS) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
                status: STATUS.FAILED,
                message: result.reason || "Failed to delete TOTP authentication"
            }));
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: STATUS.SUCCESS,
            message: result.message || "TOTP authentication successfully deleted"
        }));
    } catch (error) {
        console.error("Error in deleteTotp handler:", error);
        res.statusCode = 500;
        return res.end(JSON.stringify({
            status: STATUS.FAILED,
            message: "An error occurred while deleting TOTP authentication"
        }));
    }
}

const getAuthInfo = async function (req, res) {
    try {
        let email = req.params.email;
        if (!email) {
            if (!req.email) {
                res.statusCode = 401;
                return res.end(JSON.stringify({
                    status: STATUS.FAILED,
                    message: "Authentication required"
                }));
            }
            email = req.email;
        }
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await userLoginClient.getAuthInfo(email);

        if (result.status !== STATUS.SUCCESS) {
            throw new Error(result.reason || "Failed to get authentication information");
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: STATUS.SUCCESS,
            userExists: result.userExists,
            authMethods: result.authMethods,
            activeAuthType: result.activeAuthType,
            authMetadata: result.authMetadata
        }));

    } catch (err) {
        logger.error(`Error in getAuthInfo for ${req.params?.email || 'unknown'}: ${err.message}`, err.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
    }
}

const getPublicAuthInfo = async function (req, res) {
    try {
        let email = req.params.email;
        if (!email) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
                status: STATUS.FAILED,
                message: "No email provided"
            }));
        }
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await userLoginClient.getPublicAuthInfo(email);

        if (result.status !== STATUS.SUCCESS) {
            throw new Error(result.reason || "Failed to get authentication types");
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: STATUS.SUCCESS,
            userExists: result.userExists,
            authMethods: result.authMethods
        }));

    } catch (err) {
        logger.error(`Error in getPublicAuthInfo for ${req.params?.email || 'unknown'}: ${err.message}`, err.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
    }
}

const generatePasskeyLoginOptions = async function (req, res) {
    try {
        let email = req.params.email;
        if (!email) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
                status: STATUS.FAILED,
                message: "No email provided"
            }));
        }
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        const userLoginClient = await initAPIClient(req, constants.USER_PLUGIN);
        const result = await userLoginClient.generatePasskeyChallenge(email);

        if (result.status !== STATUS.SUCCESS) {
            const statusCode = result.reason === ERROR_REASONS.USER_NOT_EXISTS ? 404 :
                result.reason === "User does not have passkey authentication enabled" ? 400 : 500;
            res.statusCode = statusCode;
            return res.end(JSON.stringify({
                status: STATUS.FAILED,
                message: result.reason
            }));
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: STATUS.SUCCESS,
            publicKeyCredentialRequestOptions: result.publicKeyCredentialRequestOptions,
            challengeKey: result.challengeKey
        }));

    } catch (err) {
        logger.error(`Error in generatePasskeyLoginOptions for ${req.params.email}: ${err.message}`, err.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
    }
}

module.exports = {
    loginWithEmailCode,
    loginWithPasskey,
    loginWithTotp,
    sendCodeByEmail,
    getUserInfo,
    logout,
    setUserInfo,
    generatePasskeySetupOptions,
    addPasskey,
    deletePasskey,
    setupTotp,
    enableTotp,
    deleteTotp,
    getAuthInfo,
    getPublicAuthInfo,
    generatePasskeyLoginOptions
}
