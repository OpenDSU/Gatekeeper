const ipRequestCounts = new Map();
const MAX_REQUESTS_PER_WINDOW = 15; // Max requests allowed
const WINDOW_SIZE_IN_SECONDS = 60; // Window size in seconds
const CLEANUP_INTERVAL = WINDOW_SIZE_IN_SECONDS * 1000; // Cleanup interval in milliseconds

const SENSITIVE_PATHS_REGEX = [
    /\/generateAuthCode$/, // POST
    /\/walletLogin$/, // POST
    /\/userExists\/[^/]+$/, // GET
    /\/registerNewPasskey$/, // POST
    /\/registerTotp$/, // POST
    /\/verifyTotp$/ // POST
];

function isSensitivePath(url, authApiPrefix) {
    const pathWithoutPrefix = url.startsWith(authApiPrefix) ? url.substring(authApiPrefix.length) : url;
    return SENSITIVE_PATHS_REGEX.some(regex => regex.test(pathWithoutPrefix));
}

// Cleanup old IP entries periodically
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of ipRequestCounts.entries()) {
        if (now - data.timestamp > WINDOW_SIZE_IN_SECONDS * 1000) {
            ipRequestCounts.delete(ip);
        }
    }
}, CLEANUP_INTERVAL);

async function securityMiddleware(req, res, next) {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const acceptHeader = req.headers['accept'];
    const acceptLanguageHeader = req.headers['accept-language'];
    const authApiPrefix = process.env.AUTH_API_PREFIX || '';

    // 1. Enhanced User-Agent and common browser header checks
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

    // 2. Rate limiting for specifically SENSITIVE paths
    if (isSensitivePath(req.url, authApiPrefix)) {
        const now = Date.now();
        let ipData = ipRequestCounts.get(clientIp);

        if (!ipData || (now - ipData.timestamp > WINDOW_SIZE_IN_SECONDS * 1000)) {
            ipData = { count: 1, timestamp: now };
            ipRequestCounts.set(clientIp, ipData);
        } else {
            ipData.count++;
        }

        if (ipData.count > MAX_REQUESTS_PER_WINDOW) {
            console.warn(`Blocked request from IP ${clientIp} due to rate limiting for path ${req.url}. Count: ${ipData.count}`);
            res.writeHead(429, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: "Too many requests. Please try again later." }));
        }
    }

    next();
}

module.exports = {
    securityMiddleware
}; 