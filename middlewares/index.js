const {getCookies} = require("../utils/apiUtils");
const constants = require("../utils/constants");
const process = require("process");
async function authenticationMiddleware(req, res, next) {
    let cookies = getCookies(req);
    req.sessionId = cookies['sessionId'];

    const skipAuth = ["generateAuthCode", "walletLogin", "userExists"];
    // Exclude specific routes
    const containsSubstring = skipAuth.some(substring => req.url.indexOf(substring) !== -1);
    if (containsSubstring) {
        return next(); // Skip middleware for these routes
    }

    let openDSU = require("opendsu");
    const system = openDSU.loadApi("system");
    const baseURL = system.getBaseURL();
    let client = openDSU.loadAPI("serverless").createServerlessAPIClient("*", baseURL,  process.env.SERVERLESS_ID , constants.USER_PLUGIN);
    let response = await client.checkSessionId(req.sessionId);
    if(response.status === "success"){
        req.userId = response.globalUserId;
        req.email = response.email;
        req.walletKey = response.walletKey;
        return next();
    }

    res.writeHead(401, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({operation: "unauthorized"}));
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
    bodyReader
};
