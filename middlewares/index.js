const {getCookies} = require("../utils/apiUtils");
const constants = require("../utils/constants");
const process = require("process");
async function authenticationMiddleware(req, res, next) {
    let cookies = getCookies(req);
    req.sessionId = cookies['sessionId'];

    const skipAuth = ["ready"];
    const containsSubstring = skipAuth.some(substring => req.url.indexOf(substring) !== -1);
    if (containsSubstring) {
        return next();
    }

    const whitelistMethods = ["userExists", "checkSessionId", "getUserValidationEmailCode", "authorizeUser"]
    if(req.body){
        let parsedBody = JSON.parse(req.body);
        if(parsedBody.options.authToken){
            if(parsedBody.options.authToken === process.env.SSO_SECRETS_ENCRYPTION_KEY){
                return next();
            }
        }
        for(let method of whitelistMethods){
            if(parsedBody.name === method){
                return next();
            }
        }
    }

    let openDSU = require("opendsu");
    const system = openDSU.loadApi("system");
    const baseURL = system.getBaseURL();
    let client = await openDSU.loadAPI("serverless").createServerlessAPIClient("*", baseURL,  process.env.SERVERLESS_ID , constants.USER_PLUGIN, "",{authToken: process.env.SSO_SECRETS_ENCRYPTION_KEY});
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
