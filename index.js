const path = require("path");
const auth = require("./handlers/auth");
const process = require("process");
const {getCookies} = require("./apiutils/utils");
const AUTH_API_PREFIX = process.env.AUTH_API_PREFIX;
const {authenticationMiddleware, bodyReader} = require("./middlewares");

module.exports = async function (server) {
    process.env.PERSISTENCE_FOLDER = path.join(server.rootFolder, "external-volume", "balanceData");
    process.env.AUTH_LOGS_FOLDER = path.join(server.rootFolder, "external-volume", process.env.AUTH_LOGS_FOLDER);

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
    server.use(`${AUTH_API_PREFIX}/*`, bodyReader);

    server.get(`${AUTH_API_PREFIX}/userExists/:email`, auth.userExists);
    server.get(`${AUTH_API_PREFIX}/getInfo/:email`, auth.getUserInfo);

    server.post(`${AUTH_API_PREFIX}/generateAuthCode`, auth.generateAuthCode);
    server.post(`${AUTH_API_PREFIX}/walletLogin`, auth.walletLogin);
    server.post(`${AUTH_API_PREFIX}/walletLogout`, auth.walletLogout);

    server.put(`${AUTH_API_PREFIX}/setInfo/:email`, auth.setUserInfo);
}
