const fs = require('fs').promises;
let plugins = {};

if(typeof globalThis.$$ === "undefined"){
    globalThis.$$ = {};
}

if(typeof globalThis.$$.throwError === "undefined"){
    async function throwError(error, ...args) {
        if(typeof error === "string"){
            error = new Error(error + " " + args.join(" "));
        }
        let errStr = args.join(" ");
        console.debug("Throwing err:", error, errStr);
        throw error;
    }

    if(typeof globalThis.$$ === "undefined"){
        globalThis.$$ = {
        }
    }
    $$.throwError = throwError;
}
if (typeof globalThis.$$.registerPlugin === "undefined") {
    async function registerPlugin(pluginName, path){
        let pluginInstance = await require(path).getInstance();
        if(typeof pluginInstance === "undefined"){
            $$.throwError("Invalid plugin. getInstance() method returned undefined for plugin", pluginName);
        }
        plugins[pluginName] = pluginInstance;
    }
    $$.registerPlugin = registerPlugin;
}
if (typeof globalThis.$$.loadPlugin === "undefined") {
    function loadPlugin(pluginName){
        return plugins[pluginName];
    }
    $$.loadPlugin = loadPlugin;
}

$$.clean = async function(){
    await fs.rm("./work_space_data/", { recursive: true, force: true });
    await fs.mkdir("./work_space_data/");
    await fs.rm("./logs/", { recursive: true, force: true });
    await fs.mkdir("./logs/");
}
