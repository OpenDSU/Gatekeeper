const path = require("path");
const auth = require("./handlers/auth");
const process = require("process");
const AUTH_API_PREFIX = process.env.AUTH_API_PREFIX;
const { authenticationMiddleware, bodyReader, securityMiddleware } = require("./middlewares");
const { getCookies } = require("./utils/apiUtils");
const constants = require("./utils/constants");
const crypto = require("crypto");

// New visitor detection middleware
const pendingVisitors = new Map(); // Track pending visitor IDs by IP/session

function newVisitorMiddleware(req, res, next) {
    let cookies = getCookies(req);
    
    // Check if visitor cookie already exists
    if (!cookies['visitorId']) {
        // Create a unique key for this visitor (using IP and user-agent as fallback)
        const visitorKey = req.ip || req.connection.remoteAddress || 'unknown';
        
        // Check if we're already processing this visitor
        if (pendingVisitors.has(visitorKey)) {
            // Use the existing visitor ID that's being processed
            const existingVisitorId = pendingVisitors.get(visitorKey);
            res.setHeader('Set-Cookie', `visitorId=${existingVisitorId}; Max-Age=${365 * 24 * 60 * 60}; Path=/; HttpOnly; SameSite=Strict`);
        } else {
            // Generate a new visitor ID
            const visitorId = crypto.randomBytes(32).toString("base64");
            
            // Store it temporarily to prevent duplicates
            pendingVisitors.set(visitorKey, visitorId);
            
            // Set the cookie (expires in 1 year)
            res.setHeader('Set-Cookie', `visitorId=${visitorId}; Max-Age=${365 * 24 * 60 * 60}; Path=/; HttpOnly; SameSite=Strict`);
            
            // Log new visitor for monitoring
            console.log("NEW_VISITOR", visitorId);
            
            // Clean up after a short delay to prevent memory leaks
            setTimeout(() => {
                pendingVisitors.delete(visitorKey);
            }, 5000);
        }
    }
    
    next();
}

module.exports = async function (server) {
    if (!process.env.SERVERLESS_AUTH_SECRET) {
        process.env.SERVERLESS_AUTH_SECRET = crypto.randomBytes(32).toString("base64");
    }

    process.env.PERSISTENCE_FOLDER = path.join(server.rootFolder, "external-volume", "balanceData");
    if (!process.env.SERVERLESS_STORAGE) {
        console.error("SERVERLESS_STORAGE is missing, defaults to 'external-volume/appStorage'");
        process.env.SERVERLESS_STORAGE = path.join(server.rootFolder, "external-volume", "appStorage");
    }
    if (!process.env.SERVERLESS_ID) {
        console.error("SERVERLESS_ID is missing setting default - gatekeeper");
        process.env.SERVERLESS_ID = constants.SERVERLESS_ID;
    }
    setTimeout(async () => {
        const serverlessAPI = await server.createServerlessAPI({
            urlPrefix: process.env.SERVERLESS_ID,
            storage: path.resolve(process.env.SERVERLESS_STORAGE),
            env: process.env,
        });
        server.registerServerlessProcess(process.env.SERVERLESS_ID, serverlessAPI);
    }, 0);

    // Add new visitor detection middleware for all requests
    server.use("*", newVisitorMiddleware);

    server.use(`/proxy/*`, bodyReader);
    server.use(`/proxy/*`, authenticationMiddleware);

    server.use(`${AUTH_API_PREFIX}/*`, securityMiddleware);

    server.use(`${AUTH_API_PREFIX}/*`, (req, res, next) => {
        let cookies = getCookies(req);
        req.sessionId = cookies['sessionId'];
        req.userId = cookies['userId'];
        req.walletKey = cookies['walletKey'];
        req.email = cookies['email'] ? decodeURIComponent(cookies['email']) : undefined;
        next();
    });

    server.get(`${AUTH_API_PREFIX}/getInfo`, auth.getUserInfo);

    server.get(`${AUTH_API_PREFIX}/getAuthInfo/:email`, auth.getAuthInfo);

    server.get(`${AUTH_API_PREFIX}/getPublicAuthInfo/:email`, auth.getPublicAuthInfo);

    server.use(`${AUTH_API_PREFIX}/*`, bodyReader);

    server.post(`${AUTH_API_PREFIX}/sendCodeByEmail`, auth.sendCodeByEmail);

    server.post(`${AUTH_API_PREFIX}/loginWithEmailCode`, auth.loginWithEmailCode);

    server.post(`${AUTH_API_PREFIX}/generatePasskeySetupOptions`, auth.generatePasskeySetupOptions);

    server.get(`${AUTH_API_PREFIX}/generatePasskeyLoginOptions/:email`, auth.generatePasskeyLoginOptions);

    server.post(`${AUTH_API_PREFIX}/loginWithPasskey`, auth.loginWithPasskey);

    server.post(`${AUTH_API_PREFIX}/loginWithTotp`, auth.loginWithTotp);

    server.post(`${AUTH_API_PREFIX}/logout`, auth.logout);

    server.put(`${AUTH_API_PREFIX}/setInfo`, auth.setUserInfo);

    server.post(`${AUTH_API_PREFIX}/addPasskey`, auth.addPasskey);

    server.delete(`${AUTH_API_PREFIX}/deletePasskey/:email/:credentialId`, auth.deletePasskey);

    server.delete(`${AUTH_API_PREFIX}/deleteTotp/:email`, auth.deleteTotp);

    server.post(`${AUTH_API_PREFIX}/setupTotp`, auth.setupTotp);

    server.post(`${AUTH_API_PREFIX}/enableTotp`, auth.enableTotp);
}