require("./deps/clean");
const fs = require("fs").promises;


async function loginFlow(){
    await fs.rm("./work_space_data/", { recursive: true, force: true });
    await fs.mkdir("./work_space_data/");

    await $$.registerPlugin("DefaultPersistence", "../../plugins/StandardPersistence.js");
    await $$.registerPlugin("UserLogin", "../../plugins/UserLogin.js");
    const UserLogin = $$.loadPlugin("UserLogin");

    const email = "test@test.com";
    let result = await UserLogin.createUser(email);
    console.log(result);
}

loginFlow();