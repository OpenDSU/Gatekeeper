const SystemAudit = require('../../Gatekeeper/Persisto/src/audit/SystemAudit.cjs');
const systemAudit = SystemAudit.getSystemAudit();
const roles = require("../utils/constants.js").ROLES;
async function UserLoggerPlugin() {
    let self = {};
    self.getUserLogs = async function (email) {
        let persistence = $$.loadPlugin("StandardPersistence");
        let user = await persistence.getUserLoginStatus(email);
        let activity = await systemAudit.getUserLogs(user.globalUserId);
        return activity.split(/\r?\n/);
    }

    self.userLog = async function (userId, log) {
        await systemAudit.userLog(userId, log);
    }
    self.getPublicMethods = function () {
        return [];
    }
    return self;
}

let singletonInstance = undefined;
async function getUserRole(email) {
    let persistence = $$.loadPlugin("StandardPersistence");
    let userExists = await persistence.hasUserLoginStatus(email);
    if(!userExists){
        return false;
    }
    let user = await persistence.getUserLoginStatus(email);
    return user.role;
}
module.exports = {
    getInstance: async function () {
        if (!singletonInstance) {
            singletonInstance = await UserLoggerPlugin();
        }
        return singletonInstance;
    },
    getAllow: function () {
        return async function (globalUserId, email, command, ...args) {
            switch (command) {
                case "getUserLogs":
                    if (email === args[0]) {
                        return true;
                    }
                    let role = await getUserRole(email);
                    if (!role) {
                        return false;
                    }
                    return role === roles.ADMIN;
                default:
                    return false;
            }
        }
    }
}

