module.exports = {
    SERVERLESS_ID: "gatekeeper",
    USER_PLUGIN: "UserLogin",
    CREDIT_MANAGER: "CreditManager",
    EMAIL_PLUGIN: "EmailPlugin",
    AUDIT_PLUGIN: "AuditPlugin",
    USER_LOGGER: "UserLoggerPlugin",
    ROLES: {
        "ADMIN": "sysadmin",
        "MARKETING": "marketing",
        "USER": "user",
        "VALIDATED_USER": "validated_user"
    },
    CONTROLLER_ROLES: {
        "HOLDER": "holder",
        "OWNER": "owner"
    },
    TICKET_STATUS: {
        PENDING: "pending",
        CLOSED: "closed",
        REJECTED: "rejected"
    },
    USER_CREATED: "USER_CREATED",
    USER_LOGGED_IN: "USER_LOGGED_IN",
    USER_LOGGED_OUT: "USER_LOGGED_OUT",
    USER_LOGGED_IN_FAILED: "USER_LOGGED_IN_FAILED",
    USER_LOGGED_OUT_FAILED: "USER_LOGGED_OUT_FAILED"
}
