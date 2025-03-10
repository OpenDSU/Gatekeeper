require("./deps/clean");
const fs = require("fs").promises;


async function loginFlow(){
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
       let code = await UserLogin.generateAuthorizationCode(email);
       let sessionId = await UserLogin.authorizeUser(email, code);
       console.assert(sessionId, "Login failed");
       console.log("User Logged in, sessionId:", sessionId);
       let authorized = await UserLogin.checkSessionId(email, sessionId);
       console.assert(authorized, "SessionId check failed");

       await UserLogin.logout(email);
       console.log("User logged out");
       let result  = await UserLogin.checkSessionId(email, "");
       console.assert(!result, "SessionId check failed");
    } else {
       throw new Error("User already exists");
    }
}

loginFlow().then(()=>{
    console.log("End of test");
    process.exit(0);
}).catch((e)=>{
    console.error(e)
    process.exit(1);
});

