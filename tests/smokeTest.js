require("./testInit/clean.js");

let UserLogin;
async function smokeTest() {
    await $$.clean();
    await $$.registerPlugin("StandardPersistence", "../../plugins/StandardPersistence.js");
    await $$.registerPlugin("UserLogin", "../../plugins/UserLogin.js");
    UserLogin = $$.loadPlugin("UserLogin");
    const email = "test@test.com";
    let result = await UserLogin.userExists(email);
    if (!result.userExists) {
        let user = await UserLogin.createUser(email);
        console.log("User created", user);

        let userExists = await UserLogin.userExists(email);
        if (!userExists.userExists) {
            throw new Error("userExists check failed");
        }

        let validationResult = await UserLogin.getUserValidationEmailCode(email);
        if (validationResult.status === "failed") {
            throw new Error("get email validation code failed");
        }

        let authResult = await UserLogin.loginWithEmailCode(email, validationResult.code);
        if (authResult.status === "failed") {
            throw new Error("Login failed");
        }
        console.log("User Logged in, sessionId:", authResult.sessionId);

        let authorized = await UserLogin.checkSessionId(email, authResult.sessionId);
        if (authorized.status === "failed") {
            throw new Error("SessionId check failed");
        }

        let logoutResult = await UserLogin.logout(email);
        if (logoutResult.status === "failed") {
            throw new Error("Logout failed");
        }
        console.log("User logged out");
        let result = await UserLogin.checkSessionId(email, "");
        if (result.status === "success") {
            throw new Error("SessionId check after logout should have failed");
        }

        let userInfoResult = await UserLogin.getUserInfo(email);
        if (userInfoResult.status === "failed") {
            throw new Error("getUserInfo failed");
        }
        let userInfoData = {};
        userInfoData.firstName = "John";
        userInfoData.lastName = "Doe";
        userInfoData.spaces = ["space1", "space2"];
        userInfoData.roles = {
            "space1": "owner",
            "space2": "read"
        }
        await UserLogin.setUserInfo(email, userInfoData);
        let userInfoCheck = await UserLogin.getUserInfo(email);
        if (userInfoCheck.userInfo !== userInfoData) {
            throw new Error("getUserInfo check failed");
        }

        await UserLogin.shutDown();
    } else {
        throw new Error("User already exists");
    }
}

smokeTest();


