const coreUtil = require('../Persisto/src/persistence/utils');
let MathMoney = coreUtil.MathMoney;
let parseThresholds = coreUtil.parseThresholds;
let computeStakeSublinear = coreUtil.computeStakeSublinear;
let computePercent = coreUtil.computePercent;

async function CreditManager() {
    let self = {};
    let persistence = await $$.loadPlugin("StandardPersistence");

    let tickInterval = undefined;

    self.validateUser = async function (id, level) {
        let user = await persistence.getUser(id);
        if (user.level === 0 && level > 0) {
            let unlockingPercent = 1;
            switch (level) {
                case 1:
                    unlockingPercent = 0.1;
                    break;
                default:
                    unlockingPercent = 1;
            }
            let lockedAmountUntilValidation = user.lockedAmountUntilValidation * unlockingPercent;
            user.lockedAmountUntilValidation -= lockedAmountUntilValidation;
            if (lockedAmountUntilValidation) {
                persistence.unlockPoints(id, lockedAmountUntilValidation, "User validation rewarding the user " + user.id);
            }
            let rewardInvitingUserId = user.invitingUserID;
            if (rewardInvitingUserId) {
                let lockedAmountForInvitingUser = user.lockedAmountForInvitingUser * unlockingPercent;
                user.lockedAmountForInvitingUser -= lockedAmountForInvitingUser;
                if (lockedAmountForInvitingUser) {
                    persistence.unlockPoints(rewardInvitingUserId, lockedAmountForInvitingUser, "User validation rewarding the inviter " + user.id);
                }
            }

            await persistence.setUserLevel(id, level);
            if (user.lockedAmountUntilValidation > 0) {
                await self.confiscateLockedPoints(id, user.lockedAmountUntilValidation, "After setting the user level");
            }
            if (user.lockedAmountForInvitingUser > 0) {
                await self.confiscateLockedPoints(user.invitingUserID, user.lockedAmountForInvitingUser, "After setting the user level");
            }
            await persistence.updateUser(id, {lockedAmountUntilValidation: 0, lockedAmountForInvitingUser: 0});
        }
        user.level = level;
    }

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

    self.mint = async function (amount) {
        await persistence.mintPoints(amount);
    }

    self.claimFounder = async function (userID, amount) {
        await persistence.rewardFounder(userID, amount, "Founder reward");
    }

    self.addUser = async function (email, name) {
        let user = await persistence.createUser({
            email,
            name,
            level: 0,
            lockedAmountUntilValidation: 0,
        });
        let userOrder = user.accountNumber;
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
        let user = await persistence.getUser(id);
        await persistence.confiscateLockedPoints(id, amount, reason);
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
            return true; // Implement proper permission logic here
        }
    },
    getDependencies: function () {
        return ["StandardPersistence"];
    }
}
