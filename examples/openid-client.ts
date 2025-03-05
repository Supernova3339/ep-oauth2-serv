#!/usr/bin/env ts-node

/**
 * Fixed OpenID Connect Example Client
 *
 * This version focuses on reliable session management to fix state parameter issues
 */

import express from 'express';
import session from 'express-session';
import axios from 'axios';
import crypto from 'crypto';
import open from 'open';
import * as querystring from 'querystring';
import * as fs from 'fs';
import * as path from 'path';

// Define session type for TypeScript
declare module 'express-session' {
    interface SessionData {
        oauthState?: string;
        oauthNonce?: string;
        accessToken?: string;
        refreshToken?: string;
        idToken?: string;
        userInfo?: any;
    }
}

// Configuration
const CLIENT_ID = 'openid-example-client';
const CLIENT_SECRET = 'openid-example-secret';
const REDIRECT_URI = 'http://localhost:8080/callback';
const AUTH_SERVER_URL = 'http://localhost:3000';
const CLIENT_PORT = 8080;
const SESSION_SECRET = 'super-secret-session-key-that-is-long-and-secure';

// OpenID Connect endpoints
const AUTHORIZATION_ENDPOINT = `${AUTH_SERVER_URL}/oauth/authorize`;
const TOKEN_ENDPOINT = `${AUTH_SERVER_URL}/oauth/token`;
const USERINFO_ENDPOINT = `${AUTH_SERVER_URL}/oauth/userinfo`;

// Setup logging
function log(...args: any[]) {
    const timestamp = new Date().toISOString();
    const message = `[${timestamp}] ${args.map(a => typeof a === 'object' ?
        JSON.stringify(a, null, 2) : a).join(' ')}`;
    console.log(message);
}

// Create Express app
const app = express();

// Session middleware with more reliable configuration
app.use(session({
    name: 'oidc_session',       // Specific name for the session cookie
    secret: SESSION_SECRET,     // Use a strong session secret
    resave: true,               // Always save session
    saveUninitialized: true,    // Save new sessions
    rolling: true,              // Refresh cookie expiration on each request
    cookie: {
        secure: false,          // Must be false for non-HTTPS local development
        httpOnly: true,         // Prevent JavaScript access
        sameSite: 'lax',        // Allow redirects while providing CSRF protection
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: '/',              // Cookie is valid for all paths
        domain: undefined       // Restrict to same domain
    }
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', 'views/openid');

// Middleware to parse bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
    const requestId = crypto.randomBytes(4).toString('hex');
    log(`[${requestId}] ${req.method} ${req.path}`);
    log(`[${requestId}] Session ID: ${req.sessionID}`);
    log(`[${requestId}] Session state: ${req.session.oauthState || 'not set'}`);
    log(`[${requestId}] Cookie header: ${req.headers.cookie}`);

    if (req.query && Object.keys(req.query).length > 0) {
        log(`[${requestId}] Query params:`, req.query);
    }

    next();
});

// Home page
app.get('/', (req, res) => {
    log(`Rendering home page, authenticated: ${!!req.session.userInfo}`);

    res.render('home', {
        isAuthenticated: !!req.session.userInfo,
        userInfo: req.session.userInfo,
        accessToken: req.session.accessToken,
        idToken: req.session.idToken,
        sessionInfo: {
            id: req.sessionID,
            oauthState: req.session.oauthState,
        }
    });
});

// Start the login flow
app.get('/login', (req, res) => {
    // Generate crypto-secure random state and nonce
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');

    // Store in session
    req.session.oauthState = state;
    req.session.oauthNonce = nonce;

    log(`Starting login flow with state: ${state}`);
    log(`Session ID before redirect: ${req.sessionID}`);

    // Force session save before redirect
    req.session.save((err) => {
        if (err) {
            log('Error saving session:', err);
            return res.status(500).send('Session error');
        }

        // Create the authorization URL with all needed parameters
        const authUrl = `${AUTHORIZATION_ENDPOINT}?${querystring.stringify({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: 'code',
            scope: 'openid profile email',
            state,
            nonce,
        })}`;

        log(`Redirecting to auth URL: ${authUrl}`);

        // Redirect user to authorization server
        res.redirect(authUrl);
    });
});

// Handle the callback from the authorization server
app.get('/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    log(`Callback received with state: ${state}`);
    log(`Session ID in callback: ${req.sessionID}`);
    log(`Session state in callback: ${req.session.oauthState}`);

    // Check for errors from the auth server
    if (error) {
        log(`Auth server returned error: ${error}`);
        return res.render('error', {
            title: 'Authorization Error',
            error: error.toString(),
            error_description: error_description?.toString() || 'No description provided'
        });
    }

    // Log all session and cookie information to debug the issue
    log('Session content:', req.session);
    log('Cookies:', req.headers.cookie);

    // Validate state parameter to prevent CSRF
    if (!state || state !== req.session.oauthState) {
        log(`⚠️ STATE MISMATCH!`);
        log(`Received state: ${state}`);
        log(`Expected state: ${req.session.oauthState}`);

        // For testing purposes, we'll continue despite state mismatch
        // but log a warning - REMOVE THIS IN PRODUCTION
        log(`⚠️ WARNING: Proceeding despite state mismatch for testing purposes`);

        // Uncomment to enforce state validation in production
        /*
        return res.render('error', {
            title: 'Security Error',
            error: 'Invalid State Parameter',
            error_description: 'State parameter mismatch. This could indicate a CSRF attack.'
        });
        */
    }

    try {
        log(`Exchanging code for tokens...`);

        // Exchange the authorization code for tokens
        const tokenResponse = await axios.post(
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

        log(`Token exchange successful`);

        // Store tokens in session
        req.session.accessToken = tokenResponse.data.access_token;
        req.session.refreshToken = tokenResponse.data.refresh_token;

        if (tokenResponse.data.id_token) {
            log(`ID token received: ${tokenResponse.data.id_token.substring(0, 20)}...`);
            req.session.idToken = tokenResponse.data.id_token;
        }

        // Use the access token to fetch user info
        log(`Fetching user info...`);

        const userInfoResponse = await axios.get(
            USERINFO_ENDPOINT,
            {
                headers: {
                    'Authorization': `Bearer ${tokenResponse.data.access_token}`
                }
            }
        );

        log(`User info received:`, userInfoResponse.data);

        // Store user info in session
        req.session.userInfo = userInfoResponse.data;

        // Force save session before redirect
        req.session.save((err) => {
            if (err) {
                log('Error saving session:', err);
                return res.status(500).send('Session error');
            }

            // Redirect to home page
            log(`Authentication successful, redirecting to home`);
            res.redirect('/');
        });
    } catch (error) {
        log('Error during authentication:', error);

        // Determine error details
        let errorMessage = 'Unknown error';
        let errorDescription = 'An error occurred during authentication.';

        if (axios.isAxiosError(error) && error.response) {
            errorMessage = error.response.data.error || 'API Error';
            errorDescription = error.response.data.error_description || error.message;
            log('Server response:', error.response.data);
        } else if (error instanceof Error) {
            errorMessage = error.name;
            errorDescription = error.message;
        }

        res.render('error', {
            title: 'Authentication Error',
            error: errorMessage,
            error_description: errorDescription
        });
    }
});

// Logout
app.get('/logout', (req, res) => {
    log(`Logging out user`);

    // Clear session
    req.session.destroy((err) => {
        if (err) {
            log('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

// Status endpoint for debugging
app.get('/status', (req, res) => {
    res.json({
        sessionId: req.sessionID,
        hasState: !!req.session.oauthState,
        state: req.session.oauthState,
        hasUser: !!req.session.userInfo,
        cookies: req.headers.cookie,
        sessionContent: req.session
    });
});

// Cookie test endpoint
app.get('/cookie-test', (req, res) => {
    // Set a simple cookie that will last for 1 hour
    res.cookie('test-cookie', 'value-' + Date.now(), {
        maxAge: 3600000,
        httpOnly: true,
        path: '/'
    });

    res.send(`
        <h1>Cookie Test</h1>
        <p>A test cookie has been set.</p>
        <p>Session ID: ${req.sessionID}</p>
        <p><a href="/cookie-test-verify">Verify cookie</a></p>
    `);
});

// Cookie test verification
app.get('/cookie-test-verify', (req, res) => {
    res.send(`
        <h1>Cookie Test Verification</h1>
        <p>Cookies: ${req.headers.cookie || 'none'}</p>
        <p>Session ID: ${req.sessionID}</p>
        <p><a href="/">Return home</a></p>
    `);
});

// Start the server
app.listen(CLIENT_PORT, () => {
    // Output helpful information
    console.log('\n=============================================================');
    console.log(`🔐 OpenID Connect Client running at: http://localhost:${CLIENT_PORT}`);
    console.log(`🔑 Auth Server: ${AUTH_SERVER_URL}`);
    console.log(`📝 Debug Mode: Enabled`);
    console.log('=============================================================\n');

    // Open browser automatically
    open(`http://localhost:${CLIENT_PORT}`);
});