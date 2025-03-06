const path = require("path");
const {accountExists, walletLogin, getAccount, updateAccount} = require("./handlers/auth");
const logger = $$.getLogger("index", "apis");
const process = require("process");
const AUTH_API_PREFIX = process.env.AUTH_API_PREFIX;

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

module.exports = function (server) {
    process.env.PERSISTENCE_FOLDER = path.join(server.rootFolder, "external-volume", "balanceData");
    process.env.AUTH_LOGS_FOLDER = path.join(server.rootFolder, "external-volume", process.env.AUTH_LOGS_FOLDER);

    const {authenticationMiddleware} = require("./middlewares");
    const {generateAuthCode, walletLogin, walletLogout} = require("./handlers/auth");
    const {getCookies, getEnclaveInstance, interfaceDefinition} = require("./apiutils/utils");
    const {AUTH_CODES_TABLE} = require("./tables");
    const urlPrefix = "/coreClient";
    const corePath =`../Authentication-manager/apiutils/CoreInitialisation.js`;
    const serverlessAPI = server.createServerlessAPI({urlPrefix, corePath});
    const serverUrl = serverlessAPI.getUrl();
    const serverlessAPIProxy = server.createServerlessAPIProxy(serverUrl);

    const ensureServerlessClientInitialisation = (req, res, next) => {
        req.servelessServerUrl = serverUrl;

        if (!req.servelessClients) {
            req.servelessClients = {}
        }

        const cookies = getCookies(req);
        if (!cookies.userId) {
            req.userId = "*";
            const client = require("opendsu").loadAPI("serverless").createServerlessAPIClient(req.userId, serverUrl, interfaceDefinition);
            req.servelessClients[req.userId] = client;
            return;
        }
        if (!req.servelessClients[cookies.userId]) {
            const client = require("opendsu").loadAPI("serverless").createServerlessAPIClient(cookies.userId, serverUrl, interfaceDefinition);
            req.servelessClients[cookies.userId] = client;
        }
        req.userId = cookies.userId;
    };

    server.use(`${AUTH_API_PREFIX}/*`, async function (req, res, next) {
        req.externalVolumePath = path.join(server.rootFolder, "external-volume");
        req.rootFolder = server.rootFolder
        req.coreProxyUrl = serverUrl;
        ensureServerlessClientInitialisation(req, res);
        next()
    })

    server.use(`${AUTH_API_PREFIX}/*`, authenticationMiddleware);

    server.post(`${AUTH_API_PREFIX}/generateAuthCode`, requestBodyJSONMiddleware);
    server.post(`${AUTH_API_PREFIX}/generateAuthCode`, generateAuthCode);

    server.post(`${AUTH_API_PREFIX}/walletLogin`, requestBodyJSONMiddleware);
    server.post(`${AUTH_API_PREFIX}/walletLogin`, walletLogin);

    server.post(`${AUTH_API_PREFIX}/walletLogout`, walletLogout);

    server.get(`${AUTH_API_PREFIX}/accountExists/:email`, accountExists);

    server.get(`${AUTH_API_PREFIX}/account/:email`, getAccount);

    server.put(`${AUTH_API_PREFIX}/account/:email`, requestBodyJSONMiddleware);
    server.put(`${AUTH_API_PREFIX}/account/:email`, updateAccount);

}
