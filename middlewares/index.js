const {getCookies} = require("../utils/apiUtils");

async function authenticationMiddleware(req, res, next) {
    const skipAuth = ["generateAuthCode", "walletLogin", "userExists"];
    // Exclude specific routes
    const containsSubstring = skipAuth.some(substring => req.url.indexOf(substring) !== -1);
    if (containsSubstring) {
        return next(); // Skip middleware for these routes
    }
    const cookies = getCookies(req);
    if (cookies.authKey) {
        let apihub = require("apihub");
        let secretsService = await apihub.getSecretsServiceInstanceAsync(req.serverRootFolder);
        let decodedKey = decodeURIComponent(cookies.authKey);
        if(await secretsService.validateAPIKey(decodedKey)){
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
