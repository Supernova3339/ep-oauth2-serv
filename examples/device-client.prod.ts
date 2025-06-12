#!/usr/bin/env ts-node

/**
 * OAuth 2.0 Device Authorization Grant Demo Client
 *
 * This is a simple demonstration of using the Device Authorization Grant
 * from a command-line application.
 *
 * Usage:
 *   npm run device-demo
 */

import axios, { AxiosError } from 'axios';
import open from 'open';

// Configuration
const SERVER_URL = 'https://changerawr-service-oauth2-ep.hxqcwb.easypanel.host';
const CLIENT_ID = 'e6f44b3d-9e8e-4507-bda7-f01c8c25ecdb';
const CLIENT_SECRET = 'wl8a7e4uj2h4eycvm73oxbpg2d5joz31';

// Types
interface DeviceAuthorizationResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
}

export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    id_token?: string; // OpenID Connect ID token
    scope: string;
}

interface UserInfoResponse {
    sub: string;
    email?: string;
    name?: string;
    [key: string]: any;
}

interface ErrorResponse {
    error: string;
    error_description?: string;
}

// Main function
async function main(): Promise<void> {
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
        await open(deviceAuthResponse.verification_uri_complete);

        // Step 3: Poll for token
        console.log('\nWaiting for authorization...\n');
        const token = await pollForToken(
            deviceAuthResponse.device_code,
            deviceAuthResponse.interval
        );

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
    } catch (error) {
        if (error instanceof Error) {
            console.error('Error:', error.message);
            if (axios.isAxiosError(error) && error.response) {
                console.error('Server response:', error.response.data);
            }
        } else {
            console.error('Unknown error:', error);
        }
        process.exit(1);
    }
}

// Request device code
async function requestDeviceCode(): Promise<DeviceAuthorizationResponse> {
    const response = await axios.post<DeviceAuthorizationResponse>(
        `${SERVER_URL}/oauth/device`,
        {
            client_id: CLIENT_ID,
            scope: 'profile email'
        }
    );

    return response.data;
}

// Poll for token
async function pollForToken(deviceCode: string, interval: number): Promise<TokenResponse> {
    // Add a small buffer to the interval to avoid rate limiting
    let pollInterval = (interval || 5) * 1000;

    // Poll until we get a token or an error
    while (true) {
        try {
            const response = await axios.post<TokenResponse>(
                `${SERVER_URL}/oauth/token`,
                {
                    client_id: CLIENT_ID,
                    client_secret: CLIENT_SECRET,
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                    device_code: deviceCode
                }
            );

            // If we get here, we have a token
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.data) {
                const errorData = error.response.data as ErrorResponse;

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
                        throw new Error(
                            `Authentication error: ${errorData.error}: ${errorData.error_description || ''}`
                        );
                }
            } else {
                // Unexpected error
                throw error;
            }
        }

        // Wait for the poll interval
        await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
}

// Get user info
async function getUserInfo(accessToken: string): Promise<UserInfoResponse> {
    const response = await axios.get<UserInfoResponse>(
        `${SERVER_URL}/oauth/userinfo`,
        {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        }
    );

    return response.data;
}

// Run the main function
main().catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
});