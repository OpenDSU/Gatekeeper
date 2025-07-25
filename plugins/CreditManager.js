const process = require("process");
const {generateWalletKey, getLoginStrategy} = require("../utils/pluginUtils");
const {AUTH_TYPES} = require("../constants/authConstants");
const constants = require("../utils/constants.js");

async function CreditManager() {
    let self = {};
    let persistence = $$.loadPlugin("StandardPersistence");
    let rewardPlugin = $$.loadPlugin("RewardExchangePlugin");
    let tickInterval = undefined;

    self.safeTransfer = function (amount, from, to) {
        if (amount === 0) {
            return amount;
        }
        let allowed = false;
        if (from.startsWith("U")) {
            if (to.startsWith("U")) {
                allowed = true;
            } else {
                if (to.startsWith("A")) {
                    if (persistence.agentIsOwnedBy(to, from)) {
                        allowed = true;
                    }
                }
            }
        } else if (from.startsWith("A")) {
            if (to.startsWith("U")) {
                if (persistence.agentIsOwnedBy(from, to)) {
                    allowed = true;
                }
            }
        }
        if (allowed) {
            return persistence.transfer(amount, from, to, amount);
        } else {
            throw new Error("Invalid transfer from " + from + " to " + to);
        }
    }

    self.tickTack = function () {
        console.log("Tick...");
    }
    self.persistence = persistence;
    const setUpFounderLogin = async function (email, name, founderId) {
        let walletKey = generateWalletKey();
        let defaultAuthType = AUTH_TYPES.EMAIL;
        const strategy = getLoginStrategy(defaultAuthType, persistence);
        let userPayload = {
            globalUserId: founderId,
            email: email,
            walletKey: walletKey,
            authTypes: [defaultAuthType],
            passkeyCredentials: [],
            totpSecret: undefined,
            totpEnabled: false,
            totpPendingSetup: false,
            validationEmailCode: undefined,
            validationEmailCodeTimestamp: undefined,
            loginAttempts: 0,
            lastLoginAttempt: null,
            role: constants.ROLES.ADMIN
        };
        await strategy.createUser(userPayload);

        let user = await persistence.createUserLoginStatus(userPayload);
        return user;
    }

    //keep 10% (default) of the minted amount for the founder reward
    const mint = async function (amount, founderRewardPercentage = 10) {
        await persistence.mintPoints(amount);
        let founder = await persistence.createUser({
            email: process.env.SYSADMIN_EMAIL,
            name: "founder",
            invitingUserID: "",
            level: 3,
            lockedAmountUntilValidation: 0,
            lockedAmountForInvitingUser: 0
        });
        await setUpFounderLogin(founder.email, founder.name, founder.id);
        await persistence.rewardFounder(founder.id, amount / founderRewardPercentage, "Founder reward");
    }

    try {
        // TODO: OutfitinityGift specific initialization, move specific logic to a separate module
        if (!await persistence.hasUserLoginStatus(process.env.SYSADMIN_EMAIL)) {
            await mint(process.env.SYSTEM_MINT_AMOUNT, process.env.FOUNDER_PERCENTAGE);
        }
        if (await persistence.hasUserLoginStatus(process.env.SYSADMIN_EMAIL)) {
            let userStatus = await persistence.getUserLoginStatus(process.env.SYSADMIN_EMAIL);
            if (userStatus.role !== constants.ROLES.ADMIN) {
                await persistence.updateUserLoginStatus(process.env.SYSADMIN_EMAIL, {role: constants.ROLES.ADMIN});
            }
        }
    } catch (error) {
        console.warn("Error during initialization of CreditManager: ", error.message);
    }

    self.addUser = async function (email, name, referrerId) {
        let user = await persistence.createUser({
            email,
            name,
            invitingUserID: referrerId,
            level: 0,
            lockedAmountUntilValidation: 0,
            lockedAmountForInvitingUser: 0
        });
        await rewardPlugin.rewardUser(user.id, referrerId);
        return user;
    }

    self.createAccount = self.addUser;
    self.addAccount = self.addUser;

    self.transfer = function (amount, from, to) {
        if (amount === 0) {
            return;
        }
        return persistence.transfer(amount, from, to, amount);
    }

    self.getTotalBalance = async function (id) {
        const balance = await self.balance(id);
        const lockedBalance = await self.lockedBalance(id);
        return {balance, lockedBalance};
    }

    self.balance = async function (id) {
        try {
            return await persistence.getBalance(id);
        } catch (error) {
            console.error("Error getting balance for " + id + " error is " + error.message);
            return 0;
        }
    }

    self.lockedBalance = async function (id) {
        return await persistence.getLockedBalance(id);
    }

    self.getSystemAvailablePoints = async function () {
        return await persistence.getBalance("system");
    }

    self.confiscateLockedPoints = async function (id, amount, reason) {
        return await persistence.confiscateLockedPoints(id, amount, reason);
    }

    self.getUserLogs = async function (userID) {
        return persistence.getUserLogs(userID);
    }

    self.getUser = async function (userID) {
        return await persistence.getUser(userID);
    }

    self.loginEvent = function (userID, state, reason) {
        persistence.loginEvent(userID, state, reason);
    }

    self.start = function (timer = 60 * 60 * 1000) {
        tickInterval = setInterval(self.tickTack, timer);
    }

    self.stop = function () {
        clearInterval(tickInterval);
        if (persistence) {
            persistence.shutDown();
        }
    }

    self.getPublicMethods = function () {
        return [];
    }

    return self;
}

let singletonInstance = undefined;

module.exports = {
    getInstance: async function () {
        if (!singletonInstance) {
            singletonInstance = await CreditManager();
        }
        return singletonInstance;
    },
    getAllow: function () {
        return async function (globalUserId, email, command, ...args) {
            switch (command) {
                case "transfer":
                case "safeTransfer":
                    if (globalUserId === args[1]) {
                        return true;
                    }
                    return false;
                // case "claimFounder":
                case "getTotalBalance":
                case "balance":
                case "lockedBalance":
                case "confiscateLockedPoints":
                case "getUserLogs":
                case "getUser":
                case "loginEvent":
                    if (globalUserId === args[0]) {
                        return true;
                    }
                    return false;
                case "addUser":
                case "getSystemAvailablePoints":
                    return false;
                default:
                    return false;
            }
        }
    },
    getDependencies: function () {
        return ["StandardPersistence", "RewardExchangePlugin"];
    }
}
