const path = require("path");
const auth = require("./handlers/auth");
const process = require("process");
const AUTH_API_PREFIX = process.env.AUTH_API_PREFIX;
const {authenticationMiddleware, bodyReader} = require("./middlewares");
const constants = require("./utils/constants");
module.exports = async function (server) {
    process.env.PERSISTENCE_FOLDER = path.join(server.rootFolder, "external-volume", "balanceData");

    let serverUrl;
    setTimeout(async ()=>{
        const serverlessAPI = await server.createServerlessAPI({
            urlPrefix: constants.SERVERLESS_ID,
            storage: __dirname});
        serverUrl = serverlessAPI.getUrl();
        server.registerServerlessProcessUrl(constants.SERVERLESS_ID, serverUrl);
    },0);

    server.use(`${AUTH_API_PREFIX}/*`, async function (req, res, next) {
        req.serverRootFolder = server.rootFolder;
        next();
    });

    server.use(`${AUTH_API_PREFIX}/*`, authenticationMiddleware);


    server.get(`${AUTH_API_PREFIX}/userExists/:email`, auth.userExists);
    server.get(`${AUTH_API_PREFIX}/getInfo/:email`, auth.getUserInfo);

    server.use(`${AUTH_API_PREFIX}/*`, bodyReader);

    server.post(`${AUTH_API_PREFIX}/generateAuthCode`, auth.generateAuthCode);
    server.post(`${AUTH_API_PREFIX}/walletLogin`, auth.walletLogin);
    server.post(`${AUTH_API_PREFIX}/walletLogout`, auth.walletLogout);

    server.put(`${AUTH_API_PREFIX}/setInfo/:email`, auth.setUserInfo);
}
