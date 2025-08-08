const { STATUS } = require("../constants/authConstants");
const { getCookies } = require("../utils/apiUtils");
const constants = require("../utils/constants");
const process = require("process");
const { securityMiddleware } = require("./securityMiddleware");

async function authenticationMiddleware(req, res, next) {
    let openDSU = require("opendsu");
    const system = openDSU.loadApi("system");
    const baseURL = system.getBaseURL();

    let cookies = getCookies(req);
    req.sessionId = cookies['sessionId'];

    const skipAuth = ["ready", "getPublicMethods"];
    const containsSubstring = skipAuth.some(substring => req.url.indexOf(substring) !== -1);
    if (containsSubstring) {
        return next();
    }
    let parsedBody;
    if (req.body) {
        parsedBody = JSON.parse(req.body);
        if (parsedBody.options.authToken) {
            if (parsedBody.options.authToken === process.env.SERVERLESS_AUTH_SECRET) {
                return next();
            }
        }
    }
    if (!req.url.includes("/proxy/restart/")) {
        const pmUrl = `${baseURL}/proxy/getPublicMethods/${parsedBody.serverlessId}/${parsedBody.pluginName}`;
        console.log(`[Gatekeeper] GET ${pmUrl}`);
        const publicMethods = await fetch(pmUrl);
        const ct = publicMethods.headers.get('Content-Type') || '';
        console.log(`[Gatekeeper] getPublicMethods status=${publicMethods.status} content-type=${ct}`);
        const bodyText = await publicMethods.text();
        console.log(`[Gatekeeper] getPublicMethods body(<=200)=`, bodyText.slice(0, 200));
        let publicMethodsData;
        try {
            publicMethodsData = JSON.parse(bodyText);
        } catch (e) {
            console.error(`[Gatekeeper] Failed to parse getPublicMethods JSON`, e);
            throw e;
        }
        if (publicMethodsData.result.includes(parsedBody.name)) {
            return next();
        }
    }

    let client = await openDSU.loadAPI("serverless").createServerlessAPIClient("*", baseURL, process.env.SERVERLESS_ID, constants.USER_PLUGIN, "", { authToken: process.env.SERVERLESS_AUTH_SECRET, serverlessId: process.env.SERVERLESS_ID });
    let statusCode = 401;
    if (!await client.isBlockedUser(req.sessionId)) {
        let response = await client.checkSessionId(req.sessionId);
        if (response.status === STATUS.SUCCESS) {
            req.userId = response.globalUserId;
            req.email = response.email;
            req.walletKey = response.walletKey;
            return next();
        }
        console.log("DEBUG----------: Unauthorized", JSON.stringify(response));
    } else {
        statusCode = 403;
    }

    console.log("DEBUG----------: Unauthorized", req.sessionId, req.userId, req.email, req.walletKey);
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ operation: "unauthorized" }));
}

function bodyReader(request, response, next) {
    let data = "";

    request.on('data', (chunk) => {
        data += chunk;
    });

    request.on('end', () => {
        if (!data.length) {
            request.body = undefined;
            return next();
        }
        request.body = data;
        next();
    });
}

module.exports = {
    authenticationMiddleware,
    bodyReader,
    securityMiddleware
};
