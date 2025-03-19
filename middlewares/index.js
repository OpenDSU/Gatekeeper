const {getCookies} = require("../utils/apiUtils");

async function authenticationMiddleware(req, res, next) {
    let cookies = getCookies(req);
    req.sessionId = cookies['sessionId'];
    req.email = cookies['email'];
    req.walletKey = cookies['walletKey'];
    if (cookies.userId) {
        req.userId = cookies.userId;
    } else {
        req.userId = "*";
    }

    const skipAuth = ["generateAuthCode", "walletLogin", "userExists"];
    // Exclude specific routes
    const containsSubstring = skipAuth.some(substring => req.url.indexOf(substring) !== -1);
    if (containsSubstring) {
        return next(); // Skip middleware for these routes
    }
    let ssoSecret = req.headers["x-api-key"];
    if (ssoSecret) {
        let apihub = require("apihub");
        let secretsService = await apihub.getSecretsServiceInstanceAsync(req.serverRootFolder);
        if(await secretsService.validateAPIKey(ssoSecret)){
            return next();
        }
    } else {
        let openDSU = require("opendsu");
        const system = openDSU.loadApi("system");
        const baseURL = system.getBaseURL();
        let userPlugin = "UserPlugin";
        let serverlessId = "auth";
        let client = openDSU.loadAPI("serverless").createServerlessAPIClient("*", baseURL, serverlessId, userPlugin);
        let response = await client.checkSessionId(req.email, req.sessionId);
        if(response.status === "success"){
            return next();
        }
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
