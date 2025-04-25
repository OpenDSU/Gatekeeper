// Gatekeeper/handlers/auth.js
const logger = $$.getLogger("apis", "auth");
const process = require("process");
const openDSU = require('opendsu');
const system = openDSU.loadApi("system");
const baseURL = system.getBaseURL();
const resolver = openDSU.loadAPI("resolver");
const utils = require("../utils/apiUtils");
const constants = require("../utils/constants");

async function initAPIClient(req, pluginName) {
    // Pass session details if available, otherwise use '*' for unauthenticated calls
    const userId = req.userId || '*';
    const sessionId = req.sessionId || undefined; // Pass undefined if no session
    return await require("opendsu").loadAPI("serverless").createServerlessAPIClient(
        userId, baseURL, process.env.SERVERLESS_ID, pluginName, "", { sessionId: sessionId }
    );
}

const userExists = async function (req, res) {
    let response;
    try {
        let { email } = req.params;
        email = decodeURIComponent(email);
        utils.validateEmail(email);
        // userExists can be called without authentication
        let client = await initAPIClient(req, constants.USER_PLUGIN);
        response = await client.userExists(email);

        // response from UserLogin.userExists already contains the necessary fields
        // like userExists, authType, publicKeyCredentialRequestOptions, challengeKey

    } catch (err) {
        logger.error(`Error in userExists for ${req.params.email}: ${err.message}`, err.stack);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: err.message }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    // Send the full response object back
    res.end(JSON.stringify(response));
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

    // generateAuthCode (which now might create a user) can be called without authentication
    let client = await initAPIClient(req, constants.USER_PLUGIN);

    try {
        const { email, name, referrerId, authType, registrationData } = parsedData;

        // Call UserLogin: getUserValidationEmailCode for 'email', createUser for 'passkey'
        let result;
        if (authType === "passkey") {
            // This will create the user with the first passkey
            result = await client.createUser(email, name, referrerId, "passkey", registrationData);
            // User creation successful, now create DSU
            if (result.status === "success" && result.walletKey) {
                const versionlessSSI = utils.getVersionlessSSI(email, result.walletKey);
                await $$.promisify(resolver.createDSUForExistingSSI)(versionlessSSI);
                // Loading DSU might not be necessary here unless needed immediately
                // let dsu = await $$.promisify(resolver.loadDSU)(versionlessSSI);
                logger.info(`DSU created for new passkey user ${email}`);
            } else if (result.status !== "success") {
                // Handle user creation failure specifically
                throw new Error(result.reason || "Failed to create passkey user.");
            }

            // For passkey registration, no code is sent back/emailed. Success is sufficient.
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ result: "success", message: "Passkey registration successful." }));

        } else { // Default to email auth
            result = await client.getUserValidationEmailCode(email, name, referrerId);
            if (result.status === "success") {
                if (result.walletKey) { // Ensure DSU exists if user was created
                    const versionlessSSI = utils.getVersionlessSSI(email, result.walletKey);
                    // Check if DSU exists before creating
                    try {
                        await $$.promisify(resolver.loadDSU)(versionlessSSI);
                    } catch (err) {
                        // DSU doesn't exist, create it
                        await $$.promisify(resolver.createDSUForExistingSSI)(versionlessSSI);
                        logger.info(`DSU created for new email user ${email}`);
                    }
                }

                let responseMessage = { result: "success" };
                // Only include code in response for local dev or specific conditions
                // Never email passkey data!
                if (process.env.NODE_ENV === 'development' || req.headers.origin === "http://localhost:8080") {
                    responseMessage.code = result.code;
                } else {
                    let emailClient = await initAPIClient(req, constants.EMAIL_PLUGIN);
                    let subject = "Your authentication code";
                    let text = `Your authentication code is: ${result.code}`;
                    let html = `Your authentication code is: <strong>${result.code}</strong>`;
                    await emailClient.sendEmail(email, process.env.SENDGRID_SENDER_EMAIL, subject, text, html);
                    logger.info(`Sent auth code email to ${email}`);
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify(responseMessage));
            } else {
                // Handle failure from getUserValidationEmailCode (e.g., locked account)
                res.writeHead(403, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({
                    error: result.reason,
                    details: { lockTime: result.lockTime }
                }));
            }
        }

    } catch (e) {
        logger.error(`Error during generateAuthCode/createUser for ${parsedData.email}: ${e.message}`, e.stack);
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

        // Validate structure based on expected type (passkey object or email code string)
        if (!parsedData.loginMethod || (parsedData.loginMethod !== "passkey" && parsedData.loginMethod !== "emailCode")) {
            throw new Error("Missing or invalid 'loginMethod' (must be 'passkey' or 'emailCode').");
        }
        if (parsedData.loginMethod === "passkey" && (typeof parsedData.assertion !== 'object' || !parsedData.assertion.id || !parsedData.challengeKey)) {
            throw new Error("Invalid or incomplete passkey assertion data or missing challengeKey.");
        }
        if (parsedData.loginMethod === "emailCode" && typeof parsedData.code !== 'string') {
            throw new Error("Invalid or missing email code.");
        }
        if (parsedData.loginMethod === "emailCode") {
            parsedData.code = parsedData.code.trim(); // Trim email code
        }

    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        logger.debug(`Invalid login data: ${e.message}`);
        return res.end(JSON.stringify({ error: `Invalid login data: ${e.message}` }));
    }

    // walletLogin can be called without prior authentication
    let client = await initAPIClient(req, constants.USER_PLUGIN);
    try {
        const { email, loginMethod, assertion, code, challengeKey } = parsedData;
        let loginPayload = (loginMethod === "passkey") ? assertion : code;

        // Pass challengeKey only for passkey login
        let result = await client.authorizeUser(email, loginPayload, loginMethod === "passkey" ? challengeKey : undefined);

        if (result.status === "success") {
            // Login successful, create session cookies
            let cookies = utils.createAuthCookies(result.userId, result.email, result.walletKey, result.sessionId);
            res.setHeader('Set-Cookie', cookies);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success" }));
            logger.info(`User ${email} logged in successfully (${loginMethod}).`);
        } else {
            // Login failed (invalid code/passkey, locked, etc.)
            const statusCode = (result.reason === "exceeded number of attempts") ? 403 : 401;
            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                error: result.reason,
                details: { lockTime: result.lockTime } // Include lockTime if present
            }));
            logger.warn(`User ${email} login failed (${loginMethod}): ${result.reason}`);
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

    // Use authenticated client
    let client = await initAPIClient(req, constants.USER_PLUGIN);
    let email = decodeURIComponent(req.email);
    try {
        let result = await client.registerNewPasskey(email, registrationData);

        if (result.status === "success") {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ operation: "success", credentialId: result.credentialId }));
            logger.info(`Successfully registered new passkey for user ${email}`);
        } else {
            // Handle specific errors from UserLogin if any are defined, otherwise use 400
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: result.reason || "Failed to register new passkey." }));
            logger.warn(`Failed to register new passkey for user ${email}: ${result.reason}`);
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
    setUserInfo,
    registerNewPasskey // Export the new handler
}