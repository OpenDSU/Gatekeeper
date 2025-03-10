require("./deps/clean");
const fs = require("fs").promises;


async function userInfo(){
    await fs.rm("./work_space_data/", { recursive: true, force: true });
    await fs.mkdir("./work_space_data/");

    await $$.registerPlugin("DefaultPersistence", "../../plugins/StandardPersistence.js");
    await $$.registerPlugin("UserLogin", "../../plugins/UserLogin.js");
    const UserLogin = $$.loadPlugin("UserLogin");

    const email = "test@test.com";
    let userExists = await UserLogin.userExists(email);
    if(!userExists){
        let user = await UserLogin.createUser(email);
        console.log("User created", user);
        let userExists = await UserLogin.userExists(email);
        console.assert(userExists, "userExists check failed");
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
    } else {
        throw new Error("User already exists");
    }
}

userInfo().then(()=>{
    console.log("End of test");
    process.exit(0);
}).catch((e)=>{
    console.error(e)
    process.exit(1);
});

