import { Router, Request, Response } from 'express';
import { URL } from 'url';
import { csrfProtection, requireAuth, requireApiAuth } from '../middleware';
import * as storage from '../storage/memory';
import * as oauth from '../auth/oauth';
import * as easypanel from '../auth/easypanel';
import { ACCESS_TOKEN_EXPIRY } from '../config';
import * as deviceStorage from '../storage/device';
import crypto from 'crypto';

const router = Router();

// OpenID Connect Discovery endpoint
router.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
    // Dynamically build the base URL
    const protocol = req.secure ? 'https' : 'http';
    const baseUrl = `${protocol}://${req.headers.host}`;

    res.json({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/oauth/authorize`,
        token_endpoint: `${baseUrl}/oauth/token`,
        userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
        jwks_uri: `${baseUrl}/oauth/jwks`,
        token_introspection_endpoint: `${baseUrl}/oauth/introspect`,
        token_revocation_endpoint: `${baseUrl}/oauth/revoke`,
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    });
});

// JWKS (JSON Web Key Set) endpoint
router.get('/oauth/jwks', (req: Request, res: Response) => {
    // In a production environment, this would return actual keys
    // For this implementation, we'll return a minimal JWKS structure
    res.json({
        keys: [
            {
                kty: "RSA",
                use: "sig",
                kid: "default-signing-key",
                alg: "RS256",
                // These values would typically be derived from real keys
                n: "sample-modulus-value",
                e: "AQAB"
            }
        ]
    });
});

// Token Revocation endpoint (RFC 7009)
router.post('/oauth/revoke', async (req: Request, res: Response) => {
    const { token, token_type_hint } = req.body as {
        token: string;
        token_type_hint?: 'access_token' | 'refresh_token';
    };

    // Extract client credentials from Authorization header or request body
    let clientId = '';
    let clientSecret = '';

    // Check for basic auth header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
        [clientId, clientSecret] = credentials.split(':');
    } else {
        // Check request body
        clientId = req.body.client_id;
        clientSecret = req.body.client_secret;
    }

    // Validate client
    const client = oauth.validateClient(clientId, clientSecret);
    if (!client) {
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Invalid client credentials',
        });
    }

    if (!token) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Token parameter is required',
        });
    }

    // Try to revoke the token
    let revoked = false;

    if (token_type_hint === 'refresh_token' || !token_type_hint) {
        // Check if it's a refresh token
        const accessToken = storage.refreshTokens.get(token);
        if (accessToken) {
            // Remove the tokens
            storage.refreshTokens.delete(token);
            storage.removeToken(accessToken);
            revoked = true;
        }
    }

    if ((token_type_hint === 'access_token' || !token_type_hint) && !revoked) {
        // Check if it's an access token
        revoked = storage.removeToken(token);
    }

    // RFC 7009 specifies that the revocation endpoint should return 200 OK
    // regardless of whether the token was revoked or not
    return res.status(200).send();
});

// OAuth2 Device Authorization Grant (RFC 8628)
router.post('/oauth/device', async (req: Request, res: Response) => {
    const { client_id, scope } = req.body as {
        client_id: string;
        scope?: string;
    };

    // Validate client
    const client = storage.getClient(client_id);
    if (!client) {
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Invalid client',
        });
    }

    try {
        // Parse the requested scopes
        const scopes = scope ? scope.split(' ').filter(Boolean) : ['profile', 'email'];

        // Generate the verification URI
        const protocol = req.protocol;
        const host = req.get('host');
        const verificationUri = `${protocol}://${host}/device`;

        // Create device authorization
        const deviceAuth = oauth.createDeviceAuthorization(client_id, scopes, verificationUri);

        // Return the device code response
        return res.json(deviceAuth);
    } catch (error) {
        console.error('Error creating device authorization:', error);
        return res.status(500).json({
            error: 'server_error',
            error_description: 'Failed to create device authorization'
        });
    }
});

// Device verification page - styled like Easypanel
router.get('/device', csrfProtection, (req: Request, res: Response) => {
    const userCode = req.query.user_code as string | undefined;

    // Format user code if provided (add hyphen if missing)
    let formattedUserCode = userCode || '';
    if (formattedUserCode && formattedUserCode.length === 8 && !formattedUserCode.includes('-')) {
        formattedUserCode = `${formattedUserCode.substring(0, 4)}-${formattedUserCode.substring(4)}`;
    }

    res.render('device', {
        title: 'Device Authorization',
        userCode: formattedUserCode,
        csrfToken: req.session.csrfToken,
        error: null
    });
});

// Device verification form submission
router.post('/device/verify', csrfProtection, requireAuth, (req: Request, res: Response) => {
    const { user_code } = req.body as { user_code: string };

    // Clean up user code (remove hyphen if present)
    const cleanUserCode = user_code.replace(/-/g, '');

    if (!req.session.user) {
        return res.status(401).render('error', {
            error: 'unauthorized',
            error_description: 'You must be logged in to verify a device'
        });
    }

    // Get the device code from storage
    const deviceData = deviceStorage.findByUserCode(cleanUserCode);

    if (!deviceData) {
        return res.render('device', {
            title: 'Device Authorization',
            userCode: user_code,
            csrfToken: req.session.csrfToken,
            error: 'Invalid code. Please check the code and try again.'
        });
    }

    // Check if the code is expired
    if (deviceData.expiresAt < new Date()) {
        return res.render('device', {
            title: 'Device Authorization',
            userCode: user_code,
            csrfToken: req.session.csrfToken,
            error: 'This code has expired. Please request a new code on your device.'
        });
    }

    // Authorize the device code
    const success = deviceStorage.authorizeDeviceCode(cleanUserCode, req.session.user.id);

    if (!success) {
        return res.render('device', {
            title: 'Device Authorization',
            userCode: user_code,
            csrfToken: req.session.csrfToken,
            error: 'Unable to authorize this device. Please try again.'
        });
    }

    // Show success page
    res.render('device-success', {
        title: 'Device Connected',
        message: 'Your device has been successfully authorized. You can now close this window and return to your device.'
    });
});

// OAuth2 Authorization Endpoint
router.get('/oauth/authorize', csrfProtection, async (req: Request, res: Response) => {
    const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state
    } = req.query;

    // Validate request parameters
    if (response_type !== 'code') {
        return res.status(400).render('error', {
            error: 'unsupported_response_type',
            error_description: 'Only authorization code flow is supported'
        });
    }

    if (!client_id) {
        return res.status(400).render('error', {
            error: 'invalid_request',
            error_description: 'Missing client_id parameter'
        });
    }

    // Find the client
    const client = storage.getClient(client_id as string);
    if (!client) {
        return res.status(400).render('error', {
            error: 'invalid_client',
            error_description: 'Unknown client'
        });
    }

    // Validate redirect URI
    if (!redirect_uri || !oauth.validateRedirectUri(client, redirect_uri as string)) {
        return res.status(400).render('error', {
            error: 'invalid_request',
            error_description: 'Invalid redirect URI'
        });
    }

    // Check if user is authenticated
    if (!req.session.user) {
        // Store the authorization request in the session
        req.session.authRequest = {
            response_type: response_type,
            client_id: client_id,
            redirect_uri: redirect_uri,
            scope: scope,
            state: state,
        };

        // Redirect to login page
        return res.redirect('/login');
    }

    // User is authenticated, show consent page
    const requestedScopes = ((scope as string) || '').split(' ').filter(Boolean);
    const validScopes = oauth.filterScopes(client, requestedScopes);

    return res.render('consent', {
        client: client,
        scopes: validScopes,
        user: req.session.user,
        csrfToken: req.session.csrfToken,
    });
});

// OAuth2 Consent Handling
router.post('/oauth/consent', csrfProtection, requireAuth, async (req: Request, res: Response) => {
    const {
        client_id,
        redirect_uri,
        scopes,
        approved
    } = req.body as {
        client_id: string;
        redirect_uri: string;
        scopes: string;
        approved: string;
    };

    const authRequest = req.session.authRequest;

    if (!authRequest) {
        return res.status(400).render('error', {
            error: 'invalid_request',
            error_description: 'No authorization request found'
        });
    }

    // Create the redirect URL for returning to the client
    const redirectUrl = new URL(redirect_uri);

    // Check if user approved the consent
    if (approved !== 'true') {
        // User denied consent
        redirectUrl.searchParams.append('error', 'access_denied');
        redirectUrl.searchParams.append('error_description', 'The user denied the request');

        if (authRequest.state) {
            redirectUrl.searchParams.append('state', authRequest.state as string);
        }

        return res.redirect(redirectUrl.toString());
    }

    // User approved consent
    const client = storage.getClient(client_id);
    if (!client) {
        return res.status(400).render('error', {
            error: 'invalid_client',
            error_description: 'Unknown client'
        });
    }

    // Make sure user is authenticated
    if (!req.session.user) {
        return res.status(401).render('error', {
            error: 'unauthorized',
            error_description: 'User not authenticated'
        });
    }

    // Generate authorization code
    const scopeArray = scopes.split(',');
    const authCode = oauth.generateAuthorizationCode(
        client_id,
        req.session.user.id,
        redirect_uri,
        scopeArray
    );

    // Add the code to the redirect URL
    redirectUrl.searchParams.append('code', authCode.code);

    // Add state if provided
    if (authRequest.state) {
        redirectUrl.searchParams.append('state', authRequest.state as string);
    }

    // Clear the auth request from session
    delete req.session.authRequest;

    // Redirect back to the client
    return res.redirect(redirectUrl.toString());
});

// OAuth2 Token Endpoint
router.post('/oauth/token', async (req: Request, res: Response) => {
    const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        refresh_token
    } = req.body as {
        grant_type: string;
        code?: string;
        redirect_uri?: string;
        client_id: string;
        client_secret: string;
        refresh_token?: string;
    };

    // Validate client credentials
    const client = oauth.validateClient(client_id, client_secret);
    if (!client) {
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Invalid client credentials',
        });
    }

    if (grant_type === 'authorization_code') {
        // Make sure required parameters are provided
        if (!code || !redirect_uri) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'Missing required parameters',
            });
        }

        // Validate authorization code
        const authCode = oauth.validateAuthorizationCode(code, client_id, redirect_uri);
        if (!authCode) {
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Invalid authorization code',
            });
        }

        // Generate tokens
        const token = oauth.generateTokens(client_id, authCode.userId, authCode.scopes);

        // Remove the used authorization code
        storage.removeAuthorizationCode(code);

        // Return the tokens
        return res.json({
            access_token: token.accessToken,
            token_type: 'Bearer',
            expires_in: ACCESS_TOKEN_EXPIRY,
            refresh_token: token.refreshToken,
            scope: token.scopes.join(' '),
        });
    } else if (grant_type === 'refresh_token') {
        // Make sure refresh token is provided
        if (!refresh_token) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'Missing refresh token',
            });
        }

        // Refresh the token
        const token = oauth.refreshToken(refresh_token, client_id);
        if (!token) {
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Invalid refresh token',
            });
        }

        // Return the new tokens
        return res.json({
            access_token: token.accessToken,
            token_type: 'Bearer',
            expires_in: ACCESS_TOKEN_EXPIRY,
            refresh_token: token.refreshToken,
            scope: token.scopes.join(' '),
        });
    } else if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
        // Device Authorization Grant
        const { device_code } = req.body as { device_code: string };

        if (!device_code) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'Missing device_code parameter',
            });
        }

        // In a real implementation, you would check the device code against stored codes
        // For this demo, we'll always return an error that the authorization is pending
        return res.status(400).json({
            error: 'authorization_pending',
            error_description: 'The user has not yet completed the authorization',
        });
    } else {
        return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: 'Unsupported grant type',
        });
    }
});

// Token Introspection Endpoint
router.post('/oauth/introspect', async (req: Request, res: Response) => {
    const { token } = req.body as { token: string };

    if (!token) {
        return res.json({ active: false });
    }

    const accessToken = oauth.validateAccessToken(token);

    if (!accessToken) {
        return res.json({ active: false });
    }

    return res.json({
        active: true,
        client_id: accessToken.clientId,
        username: accessToken.userId,
        scope: accessToken.scopes.join(' '),
        exp: Math.floor(accessToken.expiresAt.getTime() / 1000),
    });
});

// UserInfo Endpoint
router.get('/oauth/userinfo', requireApiAuth, async (req: Request, res: Response) => {
    const token = res.locals.token;

    // Get user info from Easypanel (using admin token in a real implementation)
    const user = await easypanel.getUserById('admin-token', token.userId);

    if (!user) {
        return res.status(404).json({
            error: 'not_found',
            error_description: 'User not found',
        });
    }

    // Build response based on requested scopes
    const userInfo: any = { sub: user.id };

    if (token.scopes.includes('email')) {
        userInfo.email = user.email;
        userInfo.email_verified = true; // We assume emails are verified in Easypanel
    }

    if (token.scopes.includes('profile')) {
        userInfo.name = user.email; // Use email as name if no name available
        // Add other profile fields as needed
    }

    return res.json(userInfo);
});

export default router;