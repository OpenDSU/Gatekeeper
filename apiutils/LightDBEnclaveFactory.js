const enclave = require("opendsu").loadAPI("enclave");

function LightDBEnclaveFactory() {
    let instances = {};
    const enclaveName = "AuthManager";

    const addEnclaveInstanceInCache = (enclaveName, enclaveInstance) => {
        instances[enclaveName] = enclaveInstance;
    }

    const getEnclaveInstanceFromCache = (enclaveName) => {
        return instances[enclaveName];
    }

    const enclaveExists = (enclaveName) => {
        return !!getEnclaveInstanceFromCache(enclaveName);
    }

    this.createLightDBEnclaveAsync = async (skipCache = false) => {
        if (!skipCache && enclaveExists(enclaveName)) {
            return getEnclaveInstanceFromCache(enclaveName);
        }

        const enclave = require("opendsu").loadAPI("enclave");
        const lightDBEnclaveInstance = enclave.initialiseLightDBEnclave(enclaveName);
        try {
            await $$.promisify(lightDBEnclaveInstance.createDatabase)(enclaveName);
        } catch (e) {
            // this console.error is a little bit abusive and can make tests and spawn process, workers fail to soon....
            console.info(`Failed to create database for enclave ${enclaveName}`, e);
        }
        let hasWriteAccess;
        try {
            hasWriteAccess = await $$.promisify(lightDBEnclaveInstance.hasWriteAccess)($$.SYSTEM_IDENTIFIER);
        } catch (e) {
            throw new Error(`Failed to check write access to ${enclaveName}`);
        }

        if (!hasWriteAccess) {
            try {
                await $$.promisify(lightDBEnclaveInstance.grantWriteAccess)($$.SYSTEM_IDENTIFIER);
            } catch (e) {
                throw new Error(`Failed to grant write access to ${enclaveName}`);
            }
        }
        addEnclaveInstanceInCache(enclaveName, lightDBEnclaveInstance);
        return lightDBEnclaveInstance;
    }
}

let instance;
const getLightDBEnclaveFactoryInstance = () => {
    if (!instance) {
        instance = new LightDBEnclaveFactory();
    }
    return instance;
}
module.exports = {
    getLightDBEnclaveFactoryInstance
};
