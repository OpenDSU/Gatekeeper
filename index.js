const path = require("path");
const {accountExists, walletLogin} = require("./handlers/auth");
const logger = $$.getLogger("index", "apis");
const process = require("process");
const config = require("./config.js");
const API_URL = config.API_URL

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
    process.env.LOGS_FOLDER = path.join(server.rootFolder, "external-volume", "hatefinity-logs");

    const {getAuthenticationMiddleware} = require("./middlewares");
    const {generateAuthCode, walletLogin, walletLogout} = require("./handlers/auth");
   // const {getWalletData, getOutfinityGiftPoints} = require("./handlers/wallet");
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

    server.use(`${API_URL}/*`, async function (req, res, next) {
        req.externalVolumePath = path.join(server.rootFolder, "external-volume");
        req.rootFolder = server.rootFolder
        req.coreProxyUrl = serverUrl;
        ensureServerlessClientInitialisation(req, res);
        next()
    })

    getAuthenticationMiddleware(server);


    server.post(`${API_URL}/generateAuthCode`, requestBodyJSONMiddleware);
    server.post(`${API_URL}/generateAuthCode`, generateAuthCode);

    server.post(`${API_URL}/walletLogin`, requestBodyJSONMiddleware);
    server.post(`${API_URL}/walletLogin`, walletLogin);

    server.post(`${API_URL}/walletLogout`, walletLogout);

    server.get(`${API_URL}/accountExists/:email`, accountExists);



}
