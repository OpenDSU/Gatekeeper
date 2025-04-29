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

async function initAPIClient(req, pluginName) {
    // Pass session details if available, otherwise use '*' for unauthenticated calls
    const userId = req.userId || '*';
    const sessionId = req.sessionId || undefined; // Pass undefined if no session
    return await require("opendsu").loadAPI("serverless").createServerlessAPIClient(
        userId, baseURL, process.env.SERVERLESS_ID, pluginName, "", { sessionId: sessionId }
    );
}

// Initialize strategy factory when first needed
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

        // Initialize strategy factory if needed
        await ensureFactoryInitialized(req);

        // Use strategy factory to get user info
        const { userInfo } = await authStrategyFactory.getStrategyForUser(email);
        response = userInfo;

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
        // Further validation based on authType could be added here
        if (parsedData.authType === "passkey" && !parsedData.registrationData) {
            throw new Error("Missing registrationData for passkey signup.");
        }
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' }); // Use 400 for bad request
        logger.debug(`Invalid data for generateAuthCode: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    // Initialize strategy factory if needed
    await ensureFactoryInitialized(req);

    try {
        const { email, authType } = parsedData;

        // Get the appropriate strategy
        const strategy = authStrategyFactory.getStrategy(authType);

        // Generate authentication data for this strategy
        const result = await strategy.generateAuthData({
            ...parsedData,
            origin: req.headers.origin
        });

        // If walletKey is present, create DSU
        if (result.walletKey) {
            const versionlessSSI = utils.getVersionlessSSI(email, result.walletKey);
            await $$.promisify(resolver.createDSUForExistingSSI)(versionlessSSI);
            logger.info(`DSU created for new ${authType} user ${email}`);
        }

        // Send response
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

        // Validate login method
        if (!parsedData.loginMethod ||
            !["passkey", "emailCode", "totp"].includes(parsedData.loginMethod)) {
            throw new Error("Missing or invalid 'loginMethod'");
        }

        // Validate method-specific data
        switch (parsedData.loginMethod) {
            case "passkey":
                if (typeof parsedData.assertion !== 'object' || !parsedData.assertion.id || !parsedData.challengeKey) {
                    throw new Error("Invalid or incomplete passkey assertion data or missing challengeKey.");
                }
                break;
            case "emailCode":
                if (typeof parsedData.code !== 'string') {
                    throw new Error("Invalid or missing email code.");
                }
                parsedData.code = parsedData.code.trim();
                break;
            case "totp":
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

    // Initialize strategy factory if needed
    await ensureFactoryInitialized(req);

    try {
        const { email, loginMethod } = parsedData;

        // Map login method to strategy type
        const strategyType = loginMethod === "emailCode" ? "email" : loginMethod;

        // Get the appropriate strategy
        const strategy = authStrategyFactory.getStrategy(strategyType);

        // Call login method on the strategy
        const result = await strategy.login(parsedData);

        if (result.success) {
            // Login successful, create session cookies
            let cookies = utils.createAuthCookies(result.userId, result.email, result.walletKey, result.sessionId);
            res.setHeader('Set-Cookie', cookies);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success" }));
            logger.info(`User ${email} logged in successfully (${loginMethod}).`);
        } else {
            // Login failed (invalid code/passkey, locked, etc.)
            const statusCode = (result.error === "exceeded number of attempts") ? 403 : 401;
            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                error: result.error,
                details: { lockTime: result.lockTime } // Include lockTime if present
            }));
            logger.warn(`User ${email} login failed (${loginMethod}): ${result.error}`);
        }
    } catch (e) {
        logger.error(`Error during walletLogin for ${parsedData.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}

// New handler for registering additional passkeys (Requires existing authentication)
const registerNewPasskey = async (req, res) => {
    // This endpoint MUST be protected by authentication middleware
    if (!req.userId || !req.email) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Authentication required." }));
    }

    let registrationData;
    try {
        registrationData = JSON.parse(req.body);
        // Basic validation of the incoming credential structure
        if (!registrationData || !registrationData.id || !registrationData.rawId || !registrationData.type || !registrationData.response ||
            !registrationData.response.clientDataJSON || !registrationData.response.attestationObject) {
            throw new Error("Invalid passkey registration data structure.");
        }
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid data for registerNewPasskey: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid request data: ${e.message}` }));
    }

    // Initialize strategy factory if needed
    await ensureFactoryInitialized(req);

    let email = decodeURIComponent(req.email);
    try {
        // Get passkey strategy
        const passkeyStrategy = authStrategyFactory.getStrategy("passkey");

        // Register new passkey
        let result = await passkeyStrategy.registerNewPasskey(email, registrationData);

        if (result.success) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success", credentialId: result.credentialId }));
            logger.info(`Successfully registered new passkey for user ${email}`);
        } else {
            // Handle specific errors from UserLogin if any are defined, otherwise use 400
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: result.error || "Failed to register new passkey." }));
            logger.warn(`Failed to register new passkey for user ${email}: ${result.error}`);
        }
    } catch (e) {
        logger.error(`Error during registerNewPasskey for ${email}: ${e.message}`, e.stack);
        // Distinguish between user errors (like duplicate key) and server errors
        const statusCode = e.message.includes("already registered") ? 409 : 500; // 409 Conflict
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
}


const walletLogout = async (req, res) => {
    // This endpoint uses authentication middleware to get sessionId
    if (!req.sessionId) {
        // Although logout should clear cookies, having a session ID ensures we target the correct session
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Session information missing." }));
    }

    try {
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        await client.logout(req.sessionId);

        // Clear cookies regardless of whether the session existed on the server
        let cookies = utils.getCookies(req); // Get all cookies to clear them
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
        // Still attempt to clear cookies on error
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

// TOTP Registration handler
const registerTotp = async (req, res) => {
    // This endpoint requires authentication - only authenticated users can register TOTP
    if (!req.userId || !req.email) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Authentication required." }));
    }

    try {
        // Initialize strategy factory if needed
        await ensureFactoryInitialized(req);

        const email = decodeURIComponent(req.email);

        // Get TOTP strategy
        const totpStrategy = authStrategyFactory.getStrategy("totp");

        // Set up TOTP
        const result = await totpStrategy.setupTotp(email);

        if (result.status === "success") {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: "success",
                uri: result.uri,
                secret: result.secret
            }));
            logger.info(`TOTP setup initiated for user ${email}`);
        } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: "error",
                error: result.error || "Failed to set up TOTP"
            }));
        }
    } catch (e) {
        logger.error(`Error during TOTP registration for ${req.email}: ${e.message}`, e.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Operation failed: ${e.message}` }));
    }
};

// TOTP Verification handler
const verifyTotp = async (req, res) => {
    let verifyData;
    try {
        verifyData = JSON.parse(req.body);

        // Get verification token and user email
        const { token, email, enableTotp } = verifyData;

        if (!token || !/^[0-9]{6}$/.test(token)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: "Please enter a valid 6-digit code." }));
        }

        // If email is included, this is a login attempt
        // If not, it's a verification after registration (enableTotp will be true)
        let userEmail = email;

        // For verification after registration, use logged in user's email
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

        // Initialize strategy factory if needed
        await ensureFactoryInitialized(req);

        // Get TOTP strategy
        const totpStrategy = authStrategyFactory.getStrategy("totp");

        if (enableTotp === true) {
            // This is verification during setup - enable TOTP if verification succeeds
            const result = await totpStrategy.verifyAndEnableTotp(userEmail, token);

            if (result.success) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    status: "success",
                    message: "TOTP enabled successfully"
                }));
                logger.info(`TOTP enabled for user ${userEmail}`);
            } else {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    status: "error",
                    error: result.error || "Invalid verification code"
                }));
            }
        } else {
            // This is a login attempt using TOTP
            const loginResult = await totpStrategy.login({
                email: userEmail,
                token: token
            });

            if (loginResult.success) {
                // Login successful, create session cookies
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
                // Login failed
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

module.exports = {
    generateAuthCode,
    walletLogin,
    walletLogout,
    userExists,
    getUserInfo,
    setUserInfo,
    registerNewPasskey,
    registerTotp,
    verifyTotp
}