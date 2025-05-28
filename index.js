const path = require("path");
const auth = require("./handlers/auth");
const process = require("process");
const AUTH_API_PREFIX = process.env.AUTH_API_PREFIX;
const { authenticationMiddleware, bodyReader, securityMiddleware } = require("./middlewares");
const { getCookies } = require("./utils/apiUtils");
const constants = require("./utils/constants");

module.exports = async function (server) {
    process.env.PERSISTENCE_FOLDER = path.join(server.rootFolder, "external-volume", "balanceData");
    if (!process.env.SERVERLESS_STORAGE) {
        console.error("SERVERLESS_STORAGE is missing, defaults to 'external-volume/appStorage'");
        process.env.SERVERLESS_STORAGE = path.join(server.rootFolder, "external-volume", "appStorage");
    }
    if (!process.env.SERVERLESS_ID) {
        console.error("SERVERLESS_ID is missing setting default - gatekeeper");
        process.env.SERVERLESS_ID = constants.SERVERLESS_ID;
    }
    setTimeout(async () => {
        const serverlessAPI = await server.createServerlessAPI({
            urlPrefix: process.env.SERVERLESS_ID,
            storage: path.resolve(process.env.SERVERLESS_STORAGE),
            env: process.env,
        });
        server.registerServerlessProcess(process.env.SERVERLESS_ID, serverlessAPI);
    }, 0);
    server.use(`/proxy/*`, bodyReader);
    server.use(`/proxy/*`, authenticationMiddleware);

    server.use(`${AUTH_API_PREFIX}/*`, securityMiddleware);

    server.use(`${AUTH_API_PREFIX}/*`, (req, res, next) => {
        let cookies = getCookies(req);
        req.sessionId = cookies['sessionId'];
        req.userId = cookies['userId'];
        req.walletKey = cookies['walletKey'];
        req.email = cookies['email'] ? decodeURIComponent(cookies['email']) : undefined;
        next();
    });

    server.get(`${AUTH_API_PREFIX}/userExists/:email`, auth.userExists);

    server.get(`${AUTH_API_PREFIX}/getInfo`, auth.getUserInfo);

    server.use(`${AUTH_API_PREFIX}/*`, bodyReader);

    server.post(`${AUTH_API_PREFIX}/generateAuthCode`, auth.generateAuthCode);

    server.post(`${AUTH_API_PREFIX}/sendCodeByEmail`, auth.sendCodeByEmail);

    server.post(`${AUTH_API_PREFIX}/loginWithEmailCode`, auth.loginWithEmailCode);

    server.post(`${AUTH_API_PREFIX}/generatePasskeyChallenge`, auth.generatePasskeyChallenge);

    server.post(`${AUTH_API_PREFIX}/loginWithPasskey`, auth.loginWithPasskey);

    server.post(`${AUTH_API_PREFIX}/loginWithTotp`, auth.loginWithTotp);

    server.post(`${AUTH_API_PREFIX}/logout`, auth.walletLogout);

    server.put(`${AUTH_API_PREFIX}/setInfo`, auth.setUserInfo);

    server.post(`${AUTH_API_PREFIX}/registerNewPasskey`, auth.registerNewPasskey);

    server.delete(`${AUTH_API_PREFIX}/deletePasskey/:email/:credentialId`, auth.deletePasskey);

    server.delete(`${AUTH_API_PREFIX}/deleteTotp/:email`, auth.deleteTotp);

    server.post(`${AUTH_API_PREFIX}/registerTotp`, auth.registerTotp);

    server.post(`${AUTH_API_PREFIX}/verifyTotp`, auth.verifyTotp);

    server.get(`${AUTH_API_PREFIX}/getAuthTypes/:email`, auth.getAuthTypes);

    server.get(`${AUTH_API_PREFIX}/passKeyConfig`, async (req, res) => {
        let config = { rp_id: process.env.RP_ID, app_name: process.env.APP_NAME }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(config));
    })
}