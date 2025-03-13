const path = require("path");
const auth = require("./handlers/auth");
const process = require("process");
const {getCookies} = require("./apiutils/utils");
const AUTH_API_PREFIX = process.env.AUTH_API_PREFIX;
const USER_LOGIN_PLUGIN = "UserLogin";

function requestBodyJSONMiddleware(request, response, next) {
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

module.exports = async function (server) {
    process.env.PERSISTENCE_FOLDER = path.join(server.rootFolder, "external-volume", "balanceData");
    process.env.AUTH_LOGS_FOLDER = path.join(server.rootFolder, "external-volume", process.env.AUTH_LOGS_FOLDER);

    const {authenticationMiddleware} = require("./middlewares");
    const urlPrefix = "/coreClient";
    let serverUrl;
    setTimeout(async ()=>{
        const serverlessAPI = await server.createServerlessAPI({urlPrefix});
        serverUrl = serverlessAPI.getUrl();
        // const serverlessAPIProxy = await server.createServerlessAPIProxy(serverUrl);
    },0);

    server.use(`${AUTH_API_PREFIX}/*`, async function (req, res, next) {
        req.externalVolumePath = path.join(server.rootFolder, "external-volume");
        req.rootFolder = server.rootFolder;
        req.serverlessUrl = serverUrl;
        const cookies = getCookies(req);
        if (cookies.userId) {
            req.userId = cookies.userId;
        } else {
            req.userId = "*";
        }
        next();
    })

    server.use(`${AUTH_API_PREFIX}/*`, authenticationMiddleware);

    server.post(`${AUTH_API_PREFIX}/generateAuthCode`, requestBodyJSONMiddleware);
    server.post(`${AUTH_API_PREFIX}/generateAuthCode`, auth.generateAuthCode);

    server.post(`${AUTH_API_PREFIX}/walletLogin`, requestBodyJSONMiddleware);
    server.post(`${AUTH_API_PREFIX}/walletLogin`, auth.walletLogin);

    server.post(`${AUTH_API_PREFIX}/walletLogout`, auth.walletLogout);

    server.get(`${AUTH_API_PREFIX}/accountExists/:email`, auth.accountExists);
    server.get(`${AUTH_API_PREFIX}/account/:email`, auth.getAccount);

    server.put(`${AUTH_API_PREFIX}/account/:email`, requestBodyJSONMiddleware);
    server.put(`${AUTH_API_PREFIX}/account/:email`, auth.updateAccount);

}
