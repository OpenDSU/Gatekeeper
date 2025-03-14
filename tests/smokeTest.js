require("./testInit/clean.js");

async function smokeTest() {
    await $$.clean();
    await $$.registerPlugin("StandardPersistence", "../../plugins/StandardPersistence.js");
    await $$.registerPlugin("UserLogin", "../../plugins/UserLogin.js");
    const UserLogin = $$.loadPlugin("UserLogin");
    const email = "test@test.com";
    let userExists = await UserLogin.userExists(email);
    if (!userExists) {
        let user = await UserLogin.createUser(email);
        console.log("User created", user);

        let userExists = await UserLogin.userExists(email);
        console.assert(userExists, "userExists check failed");
        let code = await UserLogin.generateAuthorizationCode(email);

        let sessionId = await UserLogin.authorizeUser(email, code);
        console.assert(sessionId, "Login failed");
        console.log("User Logged in, sessionId:", sessionId);

        let authorized = await UserLogin.checkSessionId(email, sessionId);
        console.assert(authorized, "SessionId check failed");

        await UserLogin.logout(email);
        console.log("User logged out");
        let result = await UserLogin.checkSessionId(email, "");
        console.assert(!result, "SessionId check failed");

        let userInfo = await UserLogin.getUserInfo(email);
        console.assert(userInfo === undefined, "userInfo check failed");
        userInfo = {};
        userInfo.firstName = "John";
        userInfo.lastName = "Doe";
        userInfo.spaces = ["space1", "space2"];
        userInfo.roles = {
            "space1": "owner",
            "space2": "read"
        }
        await UserLogin.setUserInfo(email, userInfo);
        let userInfoCheck = await UserLogin.getUserInfo(email);
        console.assert(userInfoCheck === userInfo, "userInfo check failed");
        await UserLogin.shutDown();
    } else {
       throw new Error("User already exists");
    }
}

smokeTest().then(() => {
}).catch(console.error);


