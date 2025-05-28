const logger = $$.getLogger("apis", "auth");
const process = require("process");
const openDSU = require('opendsu');
const system = openDSU.loadApi("system");
const baseURL = system.getBaseURL();
const utils = require("../utils/apiUtils");
const constants = require("../utils/constants");
const { AUTH_TYPES, STATUS } = require('../constants/authConstants');

// Shared challenge cache for passkey registration
const challengeCache = new Map();

async function initAPIClient(req, pluginName) {
    const userId = req.userId;
    const sessionId = req.sessionId || undefined;
    return await require("opendsu").loadAPI("serverless").createServerlessAPIClient(
        userId, baseURL, process.env.SERVERLESS_ID, pluginName, "", { sessionId: sessionId, email: req.email }
    );
}

async function initAPIClientAdmin(req, pluginName) {
    const userId = req.userId || '*';
    return await require("opendsu").loadAPI("serverless").createServerlessAPIClient(
        userId, baseURL, process.env.SERVERLESS_ID, pluginName, "", {
        authToken: process.env.SSO_SECRETS_ENCRYPTION_KEY,
        email: req.email
    }
    );
}

const userExists = async function (req, res) {
    try {
        let { email } = req.params;
        email = decodeURIComponent(email);
        utils.validateEmail(email);

        const userLoginClient = await initAPIClientAdmin(req, constants.USER_PLUGIN);
        const response = await userLoginClient.userExists(email);

        const responseData = {
            account_exists: response.userExists,
            activeAuthType: response.activeAuthType,
            authTypes: response.authTypes || []
        };

        // Include passkey challenge data if user has passkeys
        if (response.userExists && response.authMetadata) {
            if (response.authMetadata.publicKeyCredentialRequestOptions) {
                responseData.publicKeyCredentialRequestOptions = response.authMetadata.publicKeyCredentialRequestOptions;
            }
            if (response.authMetadata.challengeKey) {
                responseData.challengeKey = response.authMetadata.challengeKey;
            }
            // Include other auth metadata
            Object.keys(response.authMetadata).forEach(key => {
                if (key !== 'publicKeyCredentialRequestOptions' && key !== 'challengeKey') {
                    responseData[key] = response.authMetadata[key];
                }
            });
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(responseData));
    } catch (err) {
        logger.error(`Error in userExists for ${req.params.email}: ${err.message}`, err.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
    }
}

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
        const userLoginClient = await initAPIClientAdmin(req, constants.USER_PLUGIN);
        const result = await userLoginClient.getUserValidationEmailCode(email, parsedData?.name, parsedData?.referrerId);

        if (result.status === STATUS.SUCCESS) {
            let responseMessage = { status: STATUS.SUCCESS };

            if (process.env.NODE_ENV === 'development' || req.headers.origin === "http://localhost:8080") {
                responseMessage.code = result.code;
            } else {
                const emailClient = await initAPIClientAdmin(req, constants.EMAIL_PLUGIN);
                try {
                    await emailClient.sendEmail(
                        result.userId,
                        email,
                        process.env.SENDGRID_SENDER_EMAIL,
                        "Your authentication code",
                        `Your authentication code is: ${result.code}`,
                        `Your authentication code is: <strong>${result.code}</strong>`
                    );
                    logger.info(`Sent auth code email to ${email}`);
                } catch (err) {
                    logger.error(`Failed to send email to ${email}: ${err.message}`);
                }
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

const registerTotp = async (req, res) => {
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
        logger.error(`Error during TOTP registration for ${req.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

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

        const client = await initAPIClient(req, constants.USER_PLUGIN);

        if (enableTotp === true) {
            const result = await client.verifyAndEnableTotp(userEmail, token);

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
        } else {
            // This is a login attempt
            const result = await client.loginWithTotp(userEmail, token);

            if (result.status === STATUS.SUCCESS) {
                let cookies = utils.createAuthCookies(
                    result.userId,
                    result.email,
                    result.walletKey,
                    result.sessionId
                );
                res.setHeader('Set-Cookie', cookies);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ operation: "success" }));
                logger.info(`User ${userEmail} logged in successfully using TOTP.`);
            } else {
                const statusCode = (result.reason === "exceeded number of attempts") ? 403 : 401;
                res.writeHead(statusCode, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    error: result.reason,
                    details: { lockTime: result.lockTime }
                }));
                logger.warn(`User ${userEmail} TOTP login failed: ${result.reason}`);
            }
        }
    } catch (e) {
        logger.error(`Error during TOTP verification: ${e.message}`, e.stack);
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

const getAuthTypes = async function (req, res) {
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
        req.email = email;

        let userLoginClient = await initAPIClientAdmin(req, constants.USER_PLUGIN);
        const userInfoResult = await userLoginClient.getUserInfo(email);

        if (userInfoResult.status !== STATUS.SUCCESS) {
            throw new Error(userInfoResult.reason || "Failed to get user information");
        }

        const userInfo = userInfoResult.userInfo;
        const authMethods = [];

        // Email is always available
        authMethods.push({
            type: AUTH_TYPES.EMAIL,
            createdAt: userInfo.createdAt || null
        });

        // Add other auth types
        if (userInfo.authTypes && userInfo.authTypes.length > 0) {
            userInfo.authTypes.forEach(authType => {
                if (authType !== AUTH_TYPES.EMAIL && authType !== AUTH_TYPES.PASSKEY) {
                    authMethods.push({
                        type: authType,
                        createdAt: userInfo.createdAt || null
                    });
                }
            });
        }

        // Add passkey credentials
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

        // Add TOTP info
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
    userExists,
    sendCodeByEmail,
    loginWithEmailCode,
    generatePasskeySetupOptions,
    loginWithPasskey,
    loginWithTotp,
    walletLogout,
    getUserInfo,
    setUserInfo,
    addPasskey,
    deletePasskey,
    registerTotp,
    verifyTotp,
    deleteTotp,
    getAuthTypes
}
