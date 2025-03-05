let process = require("process");
let fs = require("fs");
let path = require("path");

const businessLogicCore = require("../../creditManager/GenericCore.js");
const {MathMoney} = require("../../creditManager/util/CoreUtil");

console.log("Initialisation...");
const config = require("../config.js");
const specificCoreLogic = config.SPECIFIC_CORE_LOGIC_PATH;

async function createSpecificCore() {
    let autoSaver = require('../../creditManager/persistence/AutoSaverWithStorageStrategy.js').getAutoSaverPersistence();
    await autoSaver.init();

    let persistenceModule =  require('../../creditManager/persistence/ConfigurablePersistence.js');
    let configurablePersistence = persistenceModule.getPersistentStorage(autoSaver,
        {
            "user": ["email","name", "loginEvent", "invitingUserID", "level", "lockedAmountForInvitingUser", "lockedAmountUntilValidation"],
            "agent": ["name" ,  "description",  "ownerName", "ownerURL", "ownerDescription"],
            });
    let initialiseSpecificLogic = require(`../../creditManager/addons/${specificCoreLogic}`).initialiseSpecificLogic;
    let logicCore = await businessLogicCore.createGenericCore(configurablePersistence, initialiseSpecificLogic, {
        firstUsersRewards: ["10000:1000"], // reward for the first users creating accounts
        invitationRewards: ["100000:100", "5000000:10", "1000000:1"],   // reward for the invitees when an invitation is accepted The first 5 users registered get 1 tokens, the next 15 get 1 token
        unlockedPoints: 10, // how many points are unlocked for each user
        enableUserValidation: true, // how many points are locked for each user
        defaultRewardNewUser: 10, // default reward for a new user
        initialTokenPrice: 1
    });

    logicCore.shutDown = async function(){
        await configurablePersistence.shutDown();
    }

    await logicCore.configure({
        //global system settings
        minBoostAmount: 0.001,  // minimal amount blocked required for creating a post, a comment or for any boost
        boostPerMega: 0.001, // how much is required for a boost per megabyte of content
        taxSettings:["1:0.01", "10:0.02", "100:0.05", "1000:0.1", "10000:0.2", "100000:0.5", "1000000:1"] // taxes for any creation or boost of content
    })

    return logicCore;
}

let core;

async function getCoreInstance() {
    if (!core) {
        core = await createSpecificCore();
        core.allow = require('./apiAccess.js').allow.bind(core);
    }

    return core;
}

module.exports = {
    getCoreInstance
}

//wait for 10 seconds
