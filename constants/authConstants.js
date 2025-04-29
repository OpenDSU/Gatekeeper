/**
 * Auth Constants
 * Central location for all authentication related string constants
 */

// Auth Types
const AUTH_TYPES = {
    EMAIL: "email",
    PASSKEY: "passkey",
    TOTP: "totp"
};

// Status Values
const STATUS = {
    SUCCESS: "success",
    FAILED: "failed"
};

// Error Reasons
const ERROR_REASONS = {
    // General
    ACCOUNT_NOT_EXISTS: "account doesn't exist",
    USER_NOT_EXISTS: "user doesn't exist",
    SESSION_NOT_EXISTS: "session does not exist",
    USER_SESSION_NOT_EXISTS: "user associated with session no longer exists",
    EXCEEDED_ATTEMPTS: "exceeded number of attempts",
    INVALID_CREDENTIALS: "invalid credentials",
    OPERATION_NOT_SUPPORTED: "Unsupported operation for this auth type.",
    INTERNAL_ERROR: "Internal error updating credential state.",
    METHOD_NOT_IMPLEMENTED: "Method not implemented",
    METHOD_NOT_APPLICABLE: "Method not applicable for this strategy",

    // Email specific
    INVALID_CODE: "invalid code",
    CODE_EXPIRED: "code expired",

    // Passkey specific
    INVALID_PASSKEY_DATA: "Invalid passkey login data or missing challenge key.",
    CHALLENGE_EXPIRED: "Login challenge expired or invalid. Please try again.",
    PASSKEY_NOT_REGISTERED: "Passkey not registered for this user.",
    MISSING_REGISTRATION_DATA: "Missing registration data for passkey signup.",
    PASSKEY_ALREADY_REGISTERED: "This passkey is already registered for this account.",
    USE_PASSKEY: "Account uses passkey authentication. Please use your passkey to log in.",

    // TOTP specific
    INVALID_TOTP_FORMAT: "Invalid TOTP code format.",
    TOTP_NOT_ENABLED: "TOTP not enabled for this user.",
    INVALID_TOTP_CODE: "Invalid TOTP code.",
    TOTP_SETUP_NOT_INITIATED: "TOTP setup not initiated",
    USE_TOTP: "Account uses TOTP authentication.",
    INCOMPLETE_TOTP_SETUP: "Incomplete TOTP setup"
};

// Success Messages
const SUCCESS_MESSAGES = {
    PASSKEY_REGISTRATION: "Passkey registration successful.",
    TOTP_REGISTRATION: "TOTP registration successful.",
    TOTP_ENABLED: "TOTP enabled successfully"
};

// Credential Related
const CREDENTIAL = {
    PRIMARY_PASSKEY: "Primary Passkey",
    ADDED_PASSKEY_PREFIX: "Passkey added "
};

// TOTP Settings
const TOTP_SETTINGS = {
    ISSUER: 'OutfinityGift',
    ALGORITHM: 'SHA1',
    DIGITS: 6,
    PERIOD: 30
};

// Email Subject/Content
const EMAIL = {
    SUBJECT: "Your authentication code",
    TEXT_PREFIX: "Your authentication code is: ",
    HTML_PREFIX: "Your authentication code is: <strong>"
};

// Export all constants
module.exports = {
    AUTH_TYPES,
    STATUS,
    ERROR_REASONS,
    SUCCESS_MESSAGES,
    CREDENTIAL,
    TOTP_SETTINGS,
    EMAIL
}; 