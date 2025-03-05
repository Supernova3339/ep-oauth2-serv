#!/usr/bin/env ts-node
"use strict";
/**
 * OAuth 2.0 Device Authorization Grant Demo Client
 *
 * This is a simple demonstration of using the Device Authorization Grant
 * from a command-line application.
 *
 * Usage:
 *   npm run device-demo
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
const open_1 = __importDefault(require("open"));
// Configuration
const SERVER_URL = 'http://localhost:3000';
const CLIENT_ID = 'test-client';
const CLIENT_SECRET = 'test-secret';
// Main function
async function main() {
    try {
        console.log('OAuth 2.0 Device Authorization Grant Demo\n');
        // Step 1: Request device code
        console.log('Requesting device code...');
        const deviceAuthResponse = await requestDeviceCode();
        console.log('\nDevice authorization initiated!');
        console.log(`User code: ${deviceAuthResponse.user_code}`);
        console.log(`Verification URL: ${deviceAuthResponse.verification_uri}`);
        // Step 2: Open the browser for the user
        console.log('\nOpening browser for authentication...');
        await (0, open_1.default)(deviceAuthResponse.verification_uri_complete);
        // Step 3: Poll for token
        console.log('\nWaiting for authorization...\n');
        const token = await pollForToken(deviceAuthResponse.device_code, deviceAuthResponse.interval);
        // Step 4: Use the token to access the API
        console.log('Authorization successful!');
        console.log(`Access token: ${token.access_token.substring(0, 10)}...`);
        console.log(`Refresh token: ${token.refresh_token.substring(0, 10)}...`);
        console.log(`Token expires in: ${token.expires_in} seconds`);
        console.log(`Scopes: ${token.scope}`);
        // Get user info
        console.log('\nFetching user info...');
        const userInfo = await getUserInfo(token.access_token);
        console.log('User info:', userInfo);
        console.log('\nDevice flow completed successfully!');
    }
    catch (error) {
        if (error instanceof Error) {
            console.error('Error:', error.message);
            if (axios_1.default.isAxiosError(error) && error.response) {
                console.error('Server response:', error.response.data);
            }
        }
        else {
            console.error('Unknown error:', error);
        }
        process.exit(1);
    }
}
// Request device code
async function requestDeviceCode() {
    const response = await axios_1.default.post(`${SERVER_URL}/oauth/device`, {
        client_id: CLIENT_ID,
        scope: 'profile email'
    });
    return response.data;
}
// Poll for token
async function pollForToken(deviceCode, interval) {
    // Add a small buffer to the interval to avoid rate limiting
    let pollInterval = (interval || 5) * 1000;
    // Poll until we get a token or an error
    while (true) {
        try {
            const response = await axios_1.default.post(`${SERVER_URL}/oauth/token`, {
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                device_code: deviceCode
            });
            // If we get here, we have a token
            return response.data;
        }
        catch (error) {
            if (axios_1.default.isAxiosError(error) && error.response?.data) {
                const errorData = error.response.data;
                // Handle error codes according to RFC 8628
                switch (errorData.error) {
                    case 'authorization_pending':
                        // This is expected, user hasn't approved yet
                        process.stdout.write('.');
                        break;
                    case 'slow_down':
                        // We're polling too fast, increase the interval
                        process.stdout.write('s');
                        pollInterval += 5000;
                        break;
                    case 'expired_token':
                        throw new Error('The device code has expired. Please try again.');
                    case 'access_denied':
                        throw new Error('The user denied the authorization request.');
                    default:
                        throw new Error(`Authentication error: ${errorData.error}: ${errorData.error_description || ''}`);
                }
            }
            else {
                // Unexpected error
                throw error;
            }
        }
        // Wait for the poll interval
        await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
}
// Get user info
async function getUserInfo(accessToken) {
    const response = await axios_1.default.get(`${SERVER_URL}/oauth/userinfo`, {
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    });
    return response.data;
}
// Run the main function
main().catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
});
