const {getCookies, getEnclaveInstance} = require("../apiutils/utils");

function getAuthenticationMiddleware(server) {
    const BASE_PATH = process.env.BASE_URL;
    const apihub = require("apihub");
    const skipAuthorisation = ["generateAuthCode", "walletLogin", "accountExists", "getAccount", "updateAccount"];
    server.use(`${BASE_PATH}/*`, async (req, res, next) => {
        // Exclude specific routes
        const containsSubstring = skipAuthorisation.some(substring => req.url.indexOf(substring) !== -1);
        if (containsSubstring) {
            return next(); // Skip middleware for these routes
        }
        const secretsServiceInstance = await apihub.getSecretsServiceInstanceAsync();
        const cookies = getCookies(req);
        if (cookies.wallet_token && cookies.email) {
            const enclaveInstance = await getEnclaveInstance();
            let result = await $$.promisify(enclaveInstance.getRecord)($$.SYSTEM_IDENTIFIER, "auth_codes_table", cookies.email);
            if (result && result.wallet_token === cookies.wallet_token) {
                next();
                return;
            }
        }

        res.writeHead(401, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({operation: "unauthorized"}));
    });
}

module.exports = {
    getAuthenticationMiddleware
};
