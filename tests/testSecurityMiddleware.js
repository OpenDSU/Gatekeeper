const http = require('http');
const https = require('https');
const urlParser = require('url'); // For parsing BASE_URL

// Configuration
const BASE_URL = process.env.GATEKEEPER_BASE_URL || 'http://localhost:8080'; // Adjust if your server runs elsewhere
const AUTH_API_PREFIX = process.env.AUTH_API_PREFIX || '/outfinity_gift_auth'; // Ensure this matches your Gatekeeper config
const SENSITIVE_ENDPOINT_USER_EXISTS = `${AUTH_API_PREFIX}/userExists/test@example.com`;
const SENSITIVE_ENDPOINT_GENERATE_CODE = `${AUTH_API_PREFIX}/generateAuthCode`;
const NON_SENSITIVE_ENDPOINT = '/some-other-path'; // An endpoint not covered by the security middleware

// Standard Browser-like Headers
const BROWSER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (TestEnvironment/1.0) Chrome/90.0.4430.93 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9'
};

const NON_BROWSER_USER_AGENT_HEADERS = {
    'User-Agent': 'MyCustomScript/1.0',
    'Accept': 'application/json',
    'Accept-Language': 'en-US'
};

// Helper to sleep for a specified duration
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Helper to make requests and log outcomes using native http/https modules
async function makeRequest(method, path, data = null, headers = {}, expectedStatus, testName) {
    const fullUrl = `${BASE_URL}${path}`;
    console.log(`
--- Test: ${testName} ---`);
    console.log(`Making ${method.toUpperCase()} request to ${fullUrl}`);
    if (headers && Object.keys(headers).length > 0) console.log('With headers:', headers);
    if (data) console.log('With data:', data);

    const parsedUrl = urlParser.parse(fullUrl);
    const requester = parsedUrl.protocol === 'https:' ? https : http;
    const requestData = data ? JSON.stringify(data) : null;

    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.path,
        method: method.toUpperCase(),
        headers: {
            ...headers,
            ...(requestData && { 'Content-Type': 'application/json' }),
            ...(requestData && { 'Content-Length': Buffer.byteLength(requestData) })
        }
    };

    return new Promise((resolve, reject) => {
        const req = requester.request(options, (res) => {
            let responseBody = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
                responseBody += chunk;
            });
            res.on('end', () => {
                console.log(`Response Status: ${res.statusCode}`);
                let parsedResponseBody;
                try {
                    parsedResponseBody = responseBody ? JSON.parse(responseBody) : '';
                    console.log('Response Data:', parsedResponseBody);
                } catch (parseError) {
                    console.log('Response Data (not JSON):', responseBody);
                    console.warn('Failed to parse response as JSON:', parseError.message);
                    parsedResponseBody = responseBody;
                }

                if (res.statusCode === expectedStatus) {
                    console.log(`SUCCESS: Expected status ${expectedStatus}, got ${res.statusCode}.`);
                } else {
                    console.error(`FAILURE: Expected status ${expectedStatus}, but got ${res.statusCode}.`);
                }
                resolve({ status: res.statusCode, data: parsedResponseBody });
            });
        });

        req.on('error', (error) => {
            console.error(`FAILURE: Request failed for "${testName}". Error:`, error.message);
            reject(error);
        });

        if (requestData) {
            req.write(requestData);
        }
        req.end();
    });
}

async function runTests() {
    console.log('Starting security middleware tests (native Node.js HTTP/HTTPS)...');
    console.log(`Gatekeeper URL: ${BASE_URL}${AUTH_API_PREFIX}`);
    console.log('Sensitive paths for testing User-Agent and Rate Limiting:');
    console.log(`  - ${SENSITIVE_ENDPOINT_USER_EXISTS} (GET)`);
    console.log(`  - ${SENSITIVE_ENDPOINT_GENERATE_CODE} (POST)`);
    console.log(`Non-sensitive path for testing User-Agent bypass: ${NON_SENSITIVE_ENDPOINT}`);
    console.log('---');

    // Test 1: Request without any specific headers (simulating a very basic script)
    await makeRequest('get', SENSITIVE_ENDPOINT_USER_EXISTS, null, {}, 403, 'GET without User-Agent (expect 403)');

    // Test 2: Request with User-Agent only (missing Accept, Accept-Language)
    await makeRequest('get', SENSITIVE_ENDPOINT_USER_EXISTS, null, { 'User-Agent': BROWSER_HEADERS['User-Agent'] }, 403, 'GET with User-Agent only (expect 403)');

    // Test 3: Request with User-Agent and Accept, but missing Accept-Language
    await makeRequest('get', SENSITIVE_ENDPOINT_USER_EXISTS, null, { 'User-Agent': BROWSER_HEADERS['User-Agent'], 'Accept': BROWSER_HEADERS['Accept'] }, 403, 'GET with User-Agent, Accept, missing Accept-Language (expect 403)');

    // Test 4: Request with a non-browser-like User-Agent string but with other headers
    await makeRequest('get', SENSITIVE_ENDPOINT_USER_EXISTS, null, NON_BROWSER_USER_AGENT_HEADERS, 403, 'GET with non-browser User-Agent (expect 403)');

    // Test 5: Successful GET request with all browser-like headers
    await makeRequest('get', SENSITIVE_ENDPOINT_USER_EXISTS, null, BROWSER_HEADERS, 200, 'Successful GET with browser headers (expect 200 or app error)');

    // Test 6: POST request without any specific headers
    await makeRequest('post', SENSITIVE_ENDPOINT_GENERATE_CODE, { email: 'test@example.com', authType: 'emailCode' }, {}, 403, 'POST without User-Agent (expect 403)');

    // Test 7: POST request with a non-browser-like User-Agent
    await makeRequest('post', SENSITIVE_ENDPOINT_GENERATE_CODE, { email: 'test-nonbrowser@example.com', authType: 'emailCode' }, NON_BROWSER_USER_AGENT_HEADERS, 403, 'POST with non-browser User-Agent (expect 403)');

    // Test 8: Successful POST request with all browser-like headers
    await makeRequest('post', SENSITIVE_ENDPOINT_GENERATE_CODE, { email: 'test-browser@example.com', authType: 'emailCode' }, BROWSER_HEADERS, 200, 'Successful POST with browser headers (expect 200 or app error)');

    // Test 9: User creation rate limiting - Test the 1 per hour limit
    console.log("\n--- Test: User Creation Rate Limiting (1 per hour per IP) ---");

    // First user creation request should succeed
    await makeRequest(
        'post',
        SENSITIVE_ENDPOINT_GENERATE_CODE,
        { email: 'usercreation1@example.com', authType: 'emailCode' },
        BROWSER_HEADERS,
        200,
        'First user creation request (expect 200 or app error)'
    );

    // Second user creation request should be blocked by rate limiting
    await makeRequest(
        'post',
        SENSITIVE_ENDPOINT_GENERATE_CODE,
        { email: 'usercreation2@example.com', authType: 'emailCode' },
        BROWSER_HEADERS,
        429,
        'Second user creation request (expect 429 - rate limited)'
    );

    // Third user creation request should also be blocked
    await makeRequest(
        'post',
        SENSITIVE_ENDPOINT_GENERATE_CODE,
        { email: 'usercreation3@example.com', authType: 'emailCode' },
        BROWSER_HEADERS,
        429,
        'Third user creation request (expect 429 - rate limited)'
    );

    // Test 10: General rate limiting test - Exceed rate limit for other sensitive endpoints
    console.log("\n--- Test: General Rate Limiting (15 per minute) ---");
    const MAX_REQUESTS = 15;
    const WINDOW_SECONDS = 60;

    // Use userExists endpoint to avoid hitting user creation rate limiting
    for (let i = 0; i < MAX_REQUESTS + 3; i++) {
        const expectedStatus = (i < MAX_REQUESTS) ? 200 : 429;
        await makeRequest(
            'get',
            `${AUTH_API_PREFIX}/userExists/ratelimit${i}@example.com`,
            null,
            BROWSER_HEADERS,
            expectedStatus,
            `General rate limit test ${i + 1}/${MAX_REQUESTS + 3} (expect ${expectedStatus})`
        );
        if (i >= MAX_REQUESTS && expectedStatus === 429) console.log(`General rate limit triggered at request ${i + 1}.`);
        if (i < MAX_REQUESTS - 1) await sleep(50); // Shorter delay for general rate limit tests
    }

    // Test 11: Request again after general rate limit window
    console.log(`
--- Test: Wait for general rate limit window to pass (${WINDOW_SECONDS} seconds) ---`);
    await sleep(WINDOW_SECONDS * 1000 + 2000);
    await makeRequest(
        'get',
        `${AUTH_API_PREFIX}/userExists/afterratelimit@example.com`,
        null,
        BROWSER_HEADERS,
        200,
        'GET after general rate limit window (expect 200 or app error)'
    );

    // Test 12: Request non-AUTH_API_PREFIX endpoint without any specific headers
    await makeRequest(
        'get',
        NON_SENSITIVE_ENDPOINT,
        null,
        {},
        404, // Or whatever the server returns for undefined routes not under AUTH_API_PREFIX
        'GET non-AUTH_API_PREFIX endpoint (expect not 403 from this middleware)'
    );

    console.log('\n--- All tests completed ---');
    console.log('Review output for PASS/FAILURE. Ensure Gatekeeper is running.');
    console.log('NOTE: User creation rate limiting test assumes first request is allowed,');
    console.log('      subsequent requests within the hour should be blocked with 429.');
}

runTests().catch(err => {
    console.error("Critical error during test execution:", err.message);
});

/*
How to run:
1. Ensure your Gatekeeper server (with the new securityMiddleware) is running.
2. Open your terminal in the workspace root.
3. Run the script: `node test_security_middleware.js`
   OR set environment variables first:
   `GATEKEEPER_BASE_URL=http://yourserver:port AUTH_API_PREFIX=/yourprefix node test_security_middleware.js`
*/ 