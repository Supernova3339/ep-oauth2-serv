#!/usr/bin/env ts-node

/**
 * OpenID Connect Example Client
 *
 * This example demonstrates:
 * 1. Authorization Code flow with OpenID Connect
 * 2. Triggering the consent page
 * 3. Handling the callback with code exchange
 * 4. Validating the ID token
 * 5. Fetching user info
 *
 * Usage:
 *   ts-node openid-client
 */

import express from 'express';
import session from 'express-session';
import axios from 'axios';
import crypto from 'crypto';
import open from 'open';
import * as querystring from 'querystring';

// Define session type to avoid TypeScript errors
declare module 'express-session' {
    interface SessionData {
        oauthState?: string;
        oauthNonce?: string;
        accessToken?: string;
        refreshToken?: string;
        idToken?: string;
        userInfo?: UserInfo;
    }
}

// Configuration
const CLIENT_ID = 'openid-example-client';
const CLIENT_SECRET = 'openid-example-secret';
const REDIRECT_URI = 'http://localhost:8080/callback';
const AUTH_SERVER_URL = 'http://localhost:3000';
const CLIENT_PORT = 8080;

// OpenID Connect endpoints
const AUTHORIZATION_ENDPOINT = `${AUTH_SERVER_URL}/oauth/authorize`;
const TOKEN_ENDPOINT = `${AUTH_SERVER_URL}/oauth/token`;
const USERINFO_ENDPOINT = `${AUTH_SERVER_URL}/oauth/userinfo`;

// Types
interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    id_token?: string;
    scope: string;
}

interface UserInfo {
    sub: string;
    email?: string;
    name?: string;
    [key: string]: any;
}

// Create Express app
const app = express();

// Session middleware
app.use(session({
    secret: 'openid-example-secret',
    resave: false,
    saveUninitialized: true,
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', 'views/openid');

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// Home page
app.get('/', (req, res) => {
    res.render('home', {
        isAuthenticated: !!req.session.userInfo,
        userInfo: req.session.userInfo,
        accessToken: req.session.accessToken,
        idToken: req.session.idToken
    });
});

// Start the login flow
app.get('/login', (req, res) => {
    // Generate and store state parameter to prevent CSRF
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;

    // Generate and store nonce parameter for OpenID Connect
    const nonce = crypto.randomBytes(16).toString('hex');
    req.session.oauthNonce = nonce;

    // Create the authorization URL
    const authUrl = `${AUTHORIZATION_ENDPOINT}?${querystring.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'openid profile email',
        state,
        nonce,
    })}`;

    // Redirect user to authorization server
    res.redirect(authUrl);
});

// Handle the callback from the authorization server
app.get('/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    // Check for errors
    if (error) {
        return res.render('error', {
            title: 'Authorization Error',
            error: error.toString(),
            error_description: error_description?.toString() || 'No description provided'
        });
    }

    // Validate state parameter to prevent CSRF
    if (!state || state !== req.session.oauthState) {
        return res.render('error', {
            title: 'Security Error',
            error: 'Invalid State',
            error_description: 'The state parameter does not match the expected value. This could indicate a CSRF attack.'
        });
    }

    try {
        // Exchange the authorization code for tokens
        const tokenResponse = await axios.post<TokenResponse>(
            TOKEN_ENDPOINT,
            querystring.stringify({
                grant_type: 'authorization_code',
                code: code as string,
                redirect_uri: REDIRECT_URI,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        // Store tokens in session
        req.session.accessToken = tokenResponse.data.access_token;
        req.session.refreshToken = tokenResponse.data.refresh_token;

        // Store ID token if provided
        if (tokenResponse.data.id_token) {
            req.session.idToken = tokenResponse.data.id_token;

            // For a production app, we would validate the ID token here
            // This includes verifying the signature, checking expiration, etc.
            console.log('ID Token received:', tokenResponse.data.id_token);
        }

        // Fetch user info with the access token
        const userInfoResponse = await axios.get<UserInfo>(
            USERINFO_ENDPOINT,
            {
                headers: {
                    'Authorization': `Bearer ${tokenResponse.data.access_token}`
                }
            }
        );

        // Store user info in session
        req.session.userInfo = userInfoResponse.data;

        // Redirect to home page
        res.redirect('/');
    } catch (error) {
        console.error('Error during token exchange:', error);

        // Determine error details
        let errorMessage = 'Unknown error';
        let errorDescription = 'An error occurred while processing the authorization code.';

        if (axios.isAxiosError(error) && error.response) {
            errorMessage = error.response.data.error || 'API Error';
            errorDescription = error.response.data.error_description || error.message;
        } else if (error instanceof Error) {
            errorMessage = error.name;
            errorDescription = error.message;
        }

        res.render('error', {
            title: 'Token Error',
            error: errorMessage,
            error_description: errorDescription
        });
    }
});

// Logout
app.get('/logout', (req, res) => {
    // Clear session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

// Start the server
app.listen(CLIENT_PORT, () => {
    console.log(`OpenID Connect example client running at http://localhost:${CLIENT_PORT}`);

    // Open browser automatically
    open(`http://localhost:${CLIENT_PORT}`);
});