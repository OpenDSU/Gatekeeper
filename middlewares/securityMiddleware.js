const ipUserCreationCounts = new Map();
const CLEANUP_INTERVAL = 60 * 1000;

const MAX_USER_CREATION_REQUESTS_PER_HOUR = 1;
const USER_CREATION_WINDOW_IN_SECONDS = 3600;

const USER_CREATION_PATHS_REGEX = [
    /\/generateAuthCode$/,
    /\/registerNewPasskey$/,
    /\/registerTotp$/,
    /\/verifyTotp$/
];

// Assuming getCookies is available in apiUtils
const { getCookies } = require("../utils/apiUtils");

function isUserCreationPath(url, authApiPrefix) {
    const pathWithoutPrefix = url.startsWith(authApiPrefix) ? url.substring(authApiPrefix.length) : url;
    return USER_CREATION_PATHS_REGEX.some(regex => regex.test(pathWithoutPrefix));
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of ipUserCreationCounts.entries()) {
        if (now - data.timestamp > USER_CREATION_WINDOW_IN_SECONDS * 1000) {
            ipUserCreationCounts.delete(ip);
        }
    }
}, CLEANUP_INTERVAL);

async function securityMiddleware(req, res, next) {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const acceptHeader = req.headers['accept'];
    const acceptLanguageHeader = req.headers['accept-language'];
    const authApiPrefix = process.env.AUTH_API_PREFIX || '';

    // Parse cookies from the request
    const cookies = getCookies(req);
    const userCreationMarker = cookies['user_creation_marker'];

    const ipWhitelistString = process.env.IP_WHITELIST || "";
    const whitelistedIps = ipWhitelistString.split(',').map(ip => ip.trim()).filter(ip => ip);
    if (whitelistedIps.includes(clientIp)) {
        console.log(`Request from whitelisted IP ${clientIp} bypassing security checks for path ${req.url}`);
        return next();
    }

    if (!userAgent) {
        console.warn(`Blocked request from IP ${clientIp} due to missing User-Agent for path ${req.url}`);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Access denied. User-Agent header is required for this service." }));
    }

    // Check for presence of other common browser headers
    if (!acceptHeader || !acceptLanguageHeader) {
        console.warn(`Blocked request from IP ${clientIp} (User-Agent: ${userAgent}) due to missing common browser headers (Accept, Accept-Language) for path ${req.url}`);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Access denied. Request appears to originate from a non-standard client (missing expected headers)." }));
    }

    // Check if User-Agent string contains common browser keywords.
    const isLikelyBrowser = /Mozilla|Chrome|Safari|Firefox|Edge|Opera|CriOS|FxiOS/i.test(userAgent);
    if (!isLikelyBrowser) {
        console.warn(`Blocked request from IP ${clientIp} with potentially non-browser User-Agent: ${userAgent} for path ${req.url}`);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: "Access denied. Requests must originate from a recognized web browser User-Agent." }));
    }

    if (isUserCreationPath(req.url, authApiPrefix)) {
        // Check for the user_creation_marker cookie first
        if (userCreationMarker) {
            console.warn(`Blocked user creation request from IP ${clientIp} due to existing user_creation_marker cookie for path ${req.url}`);
            res.writeHead(403, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
                error: "User creation is not allowed from this browser as an account has already been created or logged into."
            }));
        }

        const now = Date.now();
        let ipUserCreationData = ipUserCreationCounts.get(clientIp);

        if (!ipUserCreationData || (now - ipUserCreationData.timestamp > USER_CREATION_WINDOW_IN_SECONDS * 1000)) {
            // If no record or window expired, allow and record this request
            ipUserCreationData = { count: 1, timestamp: now };
            ipUserCreationCounts.set(clientIp, ipUserCreationData);
        } else {
            // Check if limit exceeded
            if (ipUserCreationData.count >= MAX_USER_CREATION_REQUESTS_PER_HOUR) {
                const timeRemaining = Math.ceil((ipUserCreationData.timestamp + USER_CREATION_WINDOW_IN_SECONDS * 1000 - now) / 1000 / 60); // minutes
                console.warn(`Blocked user creation request from IP ${clientIp} due to hourly rate limiting for path ${req.url}. Count: ${ipUserCreationData.count}, Time remaining: ${timeRemaining} minutes`);
                res.writeHead(429, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({
                    error: "Too many user creation requests. You can only create one user account per hour from this IP address.",
                    timeRemainingMinutes: timeRemaining
                }));
            }
            // If within limit, increment count
            ipUserCreationData.count++;
        }
    }

    next();
}

module.exports = {
    securityMiddleware
}; 