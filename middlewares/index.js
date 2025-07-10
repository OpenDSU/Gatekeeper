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
    if(!req.url.includes("/proxy/restart/")){
        let publicMethods = await fetch(`${baseURL}/proxy/getPublicMethods/${process.env.SERVERLESS_ID}/${parsedBody.pluginName}`);
        let publicMethodsData = await publicMethods.json();
        if (publicMethodsData.result.includes(parsedBody.name)) {
            return next();
        }
    }


    let client = await openDSU.loadAPI("serverless").createServerlessAPIClient("*", baseURL, process.env.SERVERLESS_ID, constants.USER_PLUGIN, "", { authToken: process.env.SERVERLESS_AUTH_SECRET });

    let response = await client.checkSessionId(req.sessionId);
    if (response.status === STATUS.SUCCESS) {
        req.userId = response.globalUserId;
        req.email = response.email;
        req.walletKey = response.walletKey;
        return next();
    }

    console.log("DEBUG----------: Unauthorized", JSON.stringify(response));
    console.log("DEBUG----------: Unauthorized", req.sessionId, req.userId, req.email, req.walletKey);
    res.writeHead(401, { 'Content-Type': 'application/json' });
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
