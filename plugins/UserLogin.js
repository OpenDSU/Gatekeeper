const {generateValidationCode, generateId, generateWalletKey} = require('../utils/pluginUtils');
const expiryTimeout = 5 * 60 * 1000;
const maxLoginAttempts = 5;
const process = require("process");
const loginChallenges = new Map();
const crypto = require("crypto");
const otpauth = require('../authenticator/totp/otpauth/index.cjs');

async function UserLogin() {
    let self = {};
    let persistence = await $$.loadPlugin("StandardPersistence");
    let CreditManager = await $$.loadPlugin("CreditManager");
    const {verifyRegistrationResponse, verifyAssertionResponse} = require("../authenticator/webauthn");
    self.userExists = async function (email) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (userExists) {
            let user = await persistence.getUserLoginStatus(email);
            
            // Handle different auth types
            if (user.authType === "passkey" && user.passkeyCredentials && user.passkeyCredentials.length > 0) {
                // Prepare options for navigator.credentials.get()
                const allowCredentials = user.passkeyCredentials.map(cred => ({
                    type: 'public-key',
                    id: cred.id, // Pass the base64url ID directly
                    // transports: cred.transports, // Optional: Add transports if stored
                }));

                const challenge = crypto.randomBytes(32).toString("base64url");
                const challengeKey = `login_challenge_${email}_${Date.now()}`;
                loginChallenges.set(challengeKey, challenge); // Store challenge temporarily
                // Auto-clear challenge after a timeout (e.g., 5 minutes)
                setTimeout(() => loginChallenges.delete(challengeKey), 5 * 60 * 1000);


                const publicKeyCredentialRequestOptions = {
                    challenge: challenge, // Send the actual challenge string
                    allowCredentials: allowCredentials,
                    rpId: process.env.RP_ID,
                    userVerification: 'required', // Or 'preferred'/'discouraged' based on policy
                    timeout: 60000,
                };

                // No need to update the user object with the challenge here
                // We return the options needed by the frontend directly

                return {
                    status: "success",
                    userExists: true,
                    publicKeyCredentialRequestOptions: JSON.stringify(publicKeyCredentialRequestOptions),
                    challengeKey: challengeKey, // Key to identify the challenge later
                    authType: user.authType
                }
            } else if (user.authType === "totp" && user.totpSecret) {
                // For TOTP auth type, we just need to tell the client
                return {
                    status: "success",
                    userExists: true,
                    authType: "totp"
                }
            }
            
            // User exists but uses email auth or has no passkeys registered
            return {
                status: "success",
                userExists: true,
                authType: user.authType || "email" // Default to email if authType is missing
            }
        }
        return {
            status: "success",
            userExists: false
        }
    }

    self.createUser = async function (email, name, referrerId, authType, registrationData) {
        let walletKey = generateWalletKey();
        name = name || email.split("@")[0];
        let userAsset = await CreditManager.addUser(email, name, referrerId);
        authType = authType || "email";

        let userPayload = {
            globalUserId: userAsset.id,
            email: email,
            walletKey: walletKey,
            authType: authType,
            passkeyCredentials: [], // Initialize as empty array
            validationEmailCode: undefined,
            validationEmailCodeTimestamp: undefined,
            loginAttempts: 0,
            lastLoginAttempt: null
        };

        if (authType === "passkey") {
            if (!registrationData) {
                throw new Error("Missing registration data for passkey user creation.");
            }
            try {
                // Verify the registration response FIRST
                const credentialInfo = await verifyRegistrationResponse(
                    registrationData, // The credential object from navigator.credentials.create()
                    undefined, // No challenge verification during initial registration (implicit trust)
                    process.env.ORIGIN, // Verify origin
                    process.env.RP_ID, // Verify RP ID
                    true // Require UV during registration usually
                );

                // Store the verified credential details
                userPayload.passkeyCredentials.push({
                    id: credentialInfo.credentialId.toString('base64url'), // Store as base64url
                    publicKey: credentialInfo.credentialPublicKey.toString('base64url'), // Store as base64url
                    signCount: credentialInfo.signCount,
                    aaguid: credentialInfo.aaguid.toString('base64url'),
                    fmt: credentialInfo.attestationFormat,
                    transports: registrationData.response.transports || [], // Store transports if available
                    // Add a user-friendly name later if needed, e.g., "Primary Passkey"
                    name: "Primary Passkey",
                    createdAt: new Date().toISOString()
                });

            } catch (e) {
                console.error("Passkey registration verification failed:", e);
                throw new Error(`Passkey registration verification failed: ${e.message}`);
            }
        } else if (authType === "totp") {
            // Initialize TOTP-specific fields
            userPayload.totpSecret = undefined; // Will be set by setTotpSecret
            userPayload.totpEnabled = false;
            userPayload.totpPendingSetup = true;
        } else { // authType === "email"
            userPayload.validationEmailCode = generateValidationCode(5);
            userPayload.validationEmailCodeTimestamp = new Date().toISOString();
        }

        let user = await persistence.createUserLoginStatus(userPayload);
        user.status = "success"; // Add status for consistency if needed elsewhere
        return user;
    }

    self.registerNewPasskey = async function (email, registrationData) {
        let user = await persistence.getUserLoginStatus(email);
        if (!user) {
            throw new Error("User not found for adding new passkey.");
        }
        if (user.authType !== "passkey" && user.authType !== "email" && user.authType !== "totp") {
            // We allow adding passkeys to email or totp accounts
            throw new Error("User account type does not support passkeys or is invalid.");
        }

        try {
            // Verify the new registration response
            const credentialInfo = await verifyRegistrationResponse(
                registrationData,
                undefined, // No specific challenge needed here if relying on existing session auth
                process.env.ORIGIN,
                process.env.RP_ID,
                true // Typically require UV
            );

            // Check if this credential ID already exists for this user
            if (!user.passkeyCredentials) {
                user.passkeyCredentials = []; // Initialize if not exists
            }
            const existingCredential = user.passkeyCredentials.find(cred =>
                cred.id === credentialInfo.credentialId.toString('base64url')
            );
            if (existingCredential) {
                throw new Error("This passkey is already registered for this account.");
            }

            // Add the new verified credential
            user.passkeyCredentials.push({
                id: credentialInfo.credentialId.toString('base64url'),
                publicKey: credentialInfo.credentialPublicKey.toString('base64url'),
                signCount: credentialInfo.signCount,
                aaguid: credentialInfo.aaguid.toString('base64url'),
                fmt: credentialInfo.attestationFormat,
                transports: registrationData.response.transports || [],
                name: `Passkey added ${new Date().toLocaleDateString()}`, // Simple default name
                createdAt: new Date().toISOString()
            });

            // If user was previously email-only, we keep their authType
            // They can now login with either method

            await persistence.updateUserLoginStatus(user.id, user);
            return { status: "success", credentialId: credentialInfo.credentialId.toString('base64url') };

        } catch (e) {
            console.error("Failed to register new passkey:", e);
            throw new Error(`Failed to register new passkey: ${e.message}`);
        }
    }

    async function setUserLoginStatus(user) {
        let sessionId = generateId(16);
        // Clear transient email code details if they exist
        user.validationEmailCode = undefined;
        user.validationEmailCodeTimestamp = undefined;

        // Reset login attempts on successful login
        user.loginAttempts = 0;
        user.lastLoginAttempt = null; // Clear last attempt time

        // Session creation MUST happen AFTER user update for sign count
        await persistence.updateUserLoginStatus(user.id, user);
        await persistence.createSession({
            userLoginId: user.id,
            sessionId: sessionId
        });
        return sessionId;
    }

    self.authorizeUser = async function (email, loginData, challengeKey, loginMethod = "") {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: "failed", reason: "account doesn't exist" };
        }
        let user = await persistence.getUserLoginStatus(email);
        let now = new Date().getTime();

        // Check for lock status
        if (user.loginAttempts >= maxLoginAttempts) {
            if (user.lastLoginAttempt && now < user.lastLoginAttempt + expiryTimeout) {
                // Still locked
                return {
                    status: "failed",
                    reason: "exceeded number of attempts",
                    lockTime: user.lastLoginAttempt + expiryTimeout - now
                };
            } else {
                // Lock expired, reset attempts before proceeding
                await self.resetLoginAttempts(email);
                user = await persistence.getUserLoginStatus(email); // Re-fetch user with reset attempts
            }
        }

        // If loginMethod is explicitly specified, use that for verification
        // otherwise use the user's authType
        const authMethodToUse = loginMethod || user.authType;

        if (authMethodToUse === "passkey") {
            // --- Passkey Login Verification ---
            if (!loginData || typeof loginData !== 'object' || !loginData.id || !challengeKey) {
                return { status: "failed", reason: "Invalid passkey login data or missing challenge key." };
            }

            const challenge = loginChallenges.get(challengeKey);
            if (!challenge) {
                return { status: "failed", reason: "Login challenge expired or invalid. Please try again." };
            }
            loginChallenges.delete(challengeKey); // Consume the challenge

            // Find the specific credential used for this assertion
            const credentialIdB64 = loginData.id; // Assuming loginData.id is the base64url string from assertion.id
            const storedCredential = user.passkeyCredentials.find(cred => cred.id === credentialIdB64);

            if (!storedCredential) {
                await self.incrementLoginAttempts(email); // Increment attempts on failure
                return { status: "failed", reason: "Passkey not registered for this user." };
            }

            try {
                // Prepare stored credential data for verification function
                const credentialForVerification = {
                    id: storedCredential.id, // Keep as base64url string
                    publicKey: storedCredential.publicKey, // Pass base64url public key
                    signCount: storedCredential.signCount
                };

                const verificationResult = await verifyAssertionResponse(
                    loginData, // The assertion object from navigator.credentials.get()
                    credentialForVerification,
                    challenge, // The retrieved challenge
                    process.env.ORIGIN,
                    process.env.RP_ID,
                    true // Or check user.requireUserVerification if stored per-credential
                );

                // Verification successful, update the sign count for THIS credential
                storedCredential.signCount = verificationResult.newSignCount;
                // Find the index to update the correct credential in the array
                const credIndex = user.passkeyCredentials.findIndex(cred => cred.id === storedCredential.id);
                if (credIndex > -1) {
                    user.passkeyCredentials[credIndex] = storedCredential;
                } else {
                    // Should not happen if find worked, but good to handle
                    console.error("Could not find credential index after successful verification. This indicates a logic error.");
                    throw new Error("Internal error updating credential state.");
                }

                // Create session AFTER updating the user state (including sign count)
                let sessionId = await setUserLoginStatus(user); // This also resets attempts

                return {
                    status: "success",
                    sessionId: sessionId,
                    email: email,
                    walletKey: user.walletKey,
                    userInfo: user.userInfo,
                    userId: user.globalUserId
                };

            } catch (e) {
                console.error("Passkey assertion verification failed:", e);
                await self.incrementLoginAttempts(email); // Increment attempts on failure
                return { status: "failed", reason: `Invalid passkey assertion: ${e.message}` };
            }
        } else if (authMethodToUse === "totp") {
            // --- TOTP Code Verification ---
            if (typeof loginData !== 'string') {
                return { status: "failed", reason: "Invalid TOTP code format." };
            }
            
            const totpCode = loginData; // loginData is the TOTP code string
            
            if (!user.totpSecret || !user.totpEnabled) {
                await self.incrementLoginAttempts(email);
                return { status: "failed", reason: "TOTP not enabled for this user." };
            }
            
            try {
                // Recreate TOTP instance with stored secret
                const totp = new otpauth.TOTP({
                    issuer: 'OutfinityGift',
                    label: email,
                    algorithm: 'SHA1',
                    digits: 6,
                    period: 30,
                    secret: user.totpSecret
                });
                
                // Validate the TOTP code with window of 1 period
                const delta = totp.validate({ token: totpCode, window: 1 });
                
                if (delta !== null) {
                    // TOTP code valid
                    let sessionId = await setUserLoginStatus(user); // This also resets attempts
                    
                    return {
                        status: "success",
                        sessionId: sessionId,
                        email: email,
                        walletKey: user.walletKey,
                        userInfo: user.userInfo,
                        userId: user.globalUserId
                    };
                } else {
                    // Invalid TOTP code
                    await self.incrementLoginAttempts(email);
                    return { status: "failed", reason: "Invalid TOTP code." };
                }
            } catch (e) {
                console.error("TOTP validation error:", e);
                await self.incrementLoginAttempts(email);
                return { status: "failed", reason: `TOTP validation error: ${e.message}` };
            }
        } else if (authMethodToUse === "email") {
            // --- Email Code Login Verification ---
            if (typeof loginData !== 'string') {
                return { status: "failed", reason: "Invalid login code format for email auth." };
            }
            const code = loginData; // loginData is the code string

            if (user.validationEmailCode === code) {
                if (!user.validationEmailCodeTimestamp || now - new Date(user.validationEmailCodeTimestamp).getTime() > expiryTimeout) {
                    await self.incrementLoginAttempts(email); // Treat expired code as failed attempt
                    return { status: "failed", reason: "code expired" };
                }

                // Email code valid and not expired
                let sessionId = await setUserLoginStatus(user); // This also resets attempts

                return {
                    status: "success",
                    sessionId: sessionId,
                    email: email,
                    walletKey: user.walletKey,
                    userInfo: user.userInfo,
                    userId: user.globalUserId
                };
            } else {
                // Invalid email code
                await self.incrementLoginAttempts(email);
                return { status: "failed", reason: "invalid code" };
            }
        } else {
            // Should not happen with valid authType
            return { status: "failed", reason: "Unsupported authentication type for user." };
        }
    }

    self.getUserValidationEmailCode = async function (email, name, referrerId) {
        // This function is now primarily for generating EMAIL codes.
        // Passkey registration happens via createUser or registerNewPasskey.
        let userExists = await persistence.hasUserLoginStatus(email);
        let user;

        if (!userExists) {
            // Create user with EMAIL auth type by default if called this way
            user = await self.createUser(email, name, referrerId, "email", null); // Pass null for registrationData
            return {
                status: "success",
                code: user.validationEmailCode, // Return the generated email code
                authType: "email" // Explicitly state auth type
            };
        }

        user = await persistence.getUserLoginStatus(email);

        // Check lock status only if it's an email user trying to get a new code
        if (user.authType === "email" && user.loginAttempts >= maxLoginAttempts) {
            if (user.lastLoginAttempt && new Date().getTime() < user.lastLoginAttempt + expiryTimeout) {
                return {
                    status: "failed",
                    reason: "exceeded number of attempts",
                    lockTime: user.lastLoginAttempt + expiryTimeout - new Date().getTime()
                };
            }
            // Lock expired, reset attempts
            await self.resetLoginAttempts(email);
            user = await persistence.getUserLoginStatus(email); // Re-fetch user
        }
        if (user.authType === 'email') {
            user.validationEmailCode = generateValidationCode(5);
            user.validationEmailCodeTimestamp = new Date().toISOString();
            await persistence.updateUserLoginStatus(user.id, user);
            return {
                status: "success",
                code: user.validationEmailCode,
                authType: "email"
            };
        } else if (user.authType === 'passkey') {
            // If a passkey user somehow calls this, indicate they should use passkey login
            // Or handle differently based on desired UX (e.g., allow email code as backup?)
            return {
                status: "failed",
                reason: "Account uses passkey authentication. Please use your passkey to log in.",
                authType: "passkey"
            };
        } else {
            return { status: "failed", reason: "Invalid user authentication type." };
        }
    };

    self.checkSessionId = async function (sessionId) {
        let sessionExists = await persistence.hasSession(sessionId);
        if (!sessionExists) {
            return {
                status: "failed",
                reason: "session does not exist"
            }
        }
        let session = await persistence.getSession(sessionId);
        let userExists = await persistence.hasUserLoginStatus(session.userLoginId);
        if (!userExists) {
            return {
                status: "failed",
                reason: "user doesn't exist"
            }
        }
        let user = await persistence.getUserLoginStatus(session.userLoginId);
        return {
            status: "success",
            globalUserId: user.globalUserId,
            email: user.email,
            walletKey: user.walletKey
        };
    }
    self.isSysAdmin = async function (email) {
        return process.env.SYSADMIN_EMAIL === email;
    }

    self.getUserInfo = async function (email) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return {
                status: "failed",
                reason: "user doesn't exist"
            }
        }
        let user = await persistence.getUserLoginStatus(email);
        return {
            status: "success",
            userInfo: user.userInfo || {}
        };
    }

    self.setUserInfo = async function (email, userInfo) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return {
                status: "failed",
                reason: "user doesn't exist"
            }
        }
        let user = await persistence.getUserLoginStatus(email);
        user.userInfo = userInfo;
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success"
        }
    }

    self.incrementLoginAttempts = async function (email) {
        let user = await persistence.getUserLoginStatus(email);
        if (!user.loginAttempts) {
            user.loginAttempts = 0;
        }
        user.loginAttempts++;
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success"
        }
    }

    self.resetLoginAttempts = async function (email) {
        let user = await persistence.getUserLoginStatus(email);
        user.loginAttempts = 0;
        await persistence.updateUserLoginStatus(user.id, user);
        return {
            status: "success"
        }
    }

    self.shutDown = async function () {
        await persistence.shutDown();
        return {
            status: "success"
        }
    }
<<<<<<< Updated upstream
    self.logout = async function(){
        //TODO need this?
        return {
            status: "success"
        }
    }
=======

    // TOTP Methods
    
    /**
     * Store a TOTP secret for a user
     * This is called during TOTP setup
     */
    self.setTotpSecret = async function (email, secret) {
        let userExists = await persistence.hasUserLoginStatus(email);
        let user;

        if (!userExists) {
            // Create user with TOTP auth type
            user = await self.createUser(email, null, null, "totp", null);
            return { status: "success" };
        } else {
            user = await persistence.getUserLoginStatus(email);
        }
        
        // Store the secret but don't enable TOTP yet (will be enabled after verification)
        user.totpSecret = secret;
        user.totpEnabled = false;
        user.totpPendingSetup = true;
        
        await persistence.updateUserLoginStatus(user.id, user);
        
        return { status: "success" };
    }
    
    /**
     * Verify TOTP code and enable TOTP for the user if verification succeeds
     */
    self.verifyAndEnableTotp = async function (email, token) {
        let userExists = await persistence.hasUserLoginStatus(email);
        if (!userExists) {
            return { status: "failed", reason: "User doesn't exist" };
        }
        
        let user = await persistence.getUserLoginStatus(email);
        
        if (!user.totpSecret) {
            return { status: "failed", reason: "TOTP setup not initiated" };
        }
        
        try {
            // Create TOTP instance to verify the token
            const totp = new otpauth.TOTP({
                issuer: 'OutfinityGift',
                label: email,
                algorithm: 'SHA1',
                digits: 6,
                period: 30,
                secret: user.totpSecret
            });
            
            // Validate with window of 1 period (allow ±30 seconds)
            const delta = totp.validate({ token: token, window: 1 });
            
            if (delta !== null) {
                // Verification successful, enable TOTP
                user.totpEnabled = true;
                user.totpPendingSetup = false;
                user.authType = "totp"; // Update auth type to use TOTP
                
                // Clear email auth artifacts if present
                user.validationEmailCode = undefined;
                user.validationEmailCodeTimestamp = undefined;
                
                await persistence.updateUserLoginStatus(user.id, user);
                return { status: "success" };
            } else {
                return { status: "failed", reason: "Invalid verification code" };
            }
        } catch (error) {
            console.error("TOTP verification error:", error);
            return { status: "failed", reason: `Verification error: ${error.message}` };
        }
    }

>>>>>>> Stashed changes
    return self;
}

let singletonInstance = undefined;

module.exports = {
    getInstance: async function () {
        if (!singletonInstance) {
            singletonInstance = await UserLogin();
        }
        return singletonInstance;
    },
    getAllow: function () {
        return async function (globalUserId, email, command, ...args) {
            return true;
        }
    },
    getDependencies: function () {
        return ["StandardPersistence", "CreditManager"];
    }
}
