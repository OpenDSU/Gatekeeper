const SystemAudit = require('../../Gatekeeper/Persisto/src/audit/SystemAudit.cjs');
const logsFolder = process.env.LOGS_FOLDER;
const auditFolder = process.env.AUDIT_FOLDER;
const flushInterval = process.env.FLUSH_INTERVAL || 1;
const systemAudit = SystemAudit.getSystemAudit();

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
    return self;
}

let singletonInstance = undefined;

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
                    if (globalUserId === args[0]) {
                        return true;
                    }
                    return false;
                default:
                    return false;
            }
        }
    }
}

