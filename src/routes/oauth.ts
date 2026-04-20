import { Router, Request, Response } from 'express';
import { URL } from 'url';
import { csrfProtection, requireAuth, requireApiAuth } from '../middleware';
import * as storage from '../storage/lmdb';
import * as oauth from '../auth/oauth';
import * as easypanel from '../auth/easypanel';
import { API_TOKEN } from '../config';
import * as deviceStorage from '../storage/device-lmdb';

const router = Router();

function extractBasicAuth(req: Request): { clientId: string; clientSecret: string } {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Basic ')) {
        try {
            const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf-8');
            const [clientId, clientSecret] = credentials.split(':');
            return { clientId, clientSecret };
        } catch {
            // fall through
        }
    }
    return { clientId: '', clientSecret: '' };
}

router.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
    const baseUrl = `${req.secure ? 'https' : 'http'}://${req.headers.host}`;
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

router.get('/oauth/jwks', async (req: Request, res: Response) => {
    try {
        const jwk = await oauth.getPublicJwk();
        res.json({ keys: [jwk] });
    } catch (error) {
        console.error('Error serving JWKS:', error);
        res.status(500).json({ error: 'server_error', error_description: 'Failed to generate JWKS' });
    }
});

router.post('/oauth/revoke', async (req: Request, res: Response) => {
    const { token, token_type_hint } = req.body as {
        token: string;
        token_type_hint?: 'access_token' | 'refresh_token';
    };

    const fromHeader = extractBasicAuth(req);
    const clientId = req.body.client_id || fromHeader.clientId;
    const clientSecret = req.body.client_secret || fromHeader.clientSecret;

    if (!oauth.validateClient(clientId, clientSecret)) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
    }
    if (!token) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Token parameter is required' });
    }
    if (token_type_hint === 'refresh_token' || !token_type_hint) {
        const accessToken = storage.getTokenByRefreshToken(token);
        if (accessToken) storage.removeToken(accessToken.accessToken);
    }
    if (token_type_hint === 'access_token' || !token_type_hint) {
        storage.removeToken(token);
    }
    return res.status(200).send();
});

router.post('/oauth/device', async (req: Request, res: Response) => {
    const { client_id, scope } = req.body as { client_id: string; scope?: string };
    if (!storage.getClient(client_id)) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client' });
    }
    try {
        const scopes = scope ? scope.split(' ').filter(Boolean) : ['profile', 'email'];
        const verificationUri = `${req.protocol}://${req.get('host')}/device`;
        return res.json(oauth.createDeviceAuthorization(client_id, scopes, verificationUri));
    } catch (error) {
        console.error('Error creating device authorization:', error);
        return res.status(500).json({ error: 'server_error', error_description: 'Failed to create device authorization' });
    }
});

router.post('/device/verify', csrfProtection, requireAuth, (req: Request, res: Response) => {
    const { user_code } = req.body as { user_code: string };
    const cleanUserCode = user_code.replace(/-/g, '');

    const deviceData = deviceStorage.findByUserCode(cleanUserCode);
    if (!deviceData) {
        return res.status(400).json({ error: 'invalid_code', message: 'Invalid code. Please check the code and try again.' });
    }
    if (deviceData.expiresAt < new Date()) {
        return res.status(400).json({ error: 'expired_code', message: 'This code has expired. Please request a new code on your device.' });
    }
    if (!deviceStorage.authorizeDeviceCode(cleanUserCode, req.session.user!.id)) {
        return res.status(500).json({ error: 'server_error', message: 'Unable to authorize this device. Please try again.' });
    }
    return res.json({ success: true, message: 'Your device has been successfully authorized. You can now return to your device.' });
});

router.get('/api/consent-info', requireAuth, csrfProtection, (req: Request, res: Response) => {
    const { client_id, redirect_uri, scope } = req.query;

    const client = storage.getClient(client_id as string);
    if (!client) {
        return res.status(404).json({ error: 'invalid_client', error_description: 'Unknown client' });
    }
    if (!redirect_uri || !oauth.validateRedirectUri(client, redirect_uri as string)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect URI' });
    }

    const requestedScopes = ((scope as string) || '').split(' ').filter(Boolean);
    const validScopes = oauth.filterScopes(client, requestedScopes);

    return res.json({
        client: { id: client.id, name: client.name },
        scopes: validScopes,
        user: req.session.user,
        csrfToken: req.session.csrfToken,
    });
});

router.get('/oauth/authorize', csrfProtection, async (req: Request, res: Response) => {
    const { response_type, client_id, redirect_uri, scope, state, nonce } = req.query;

    if (response_type !== 'code') {
        return res.status(400).json({ error: 'unsupported_response_type', error_description: 'Only authorization code flow is supported' });
    }
    if (!client_id) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Missing client_id parameter' });
    }

    const client = storage.getClient(client_id as string);
    if (!client) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client' });
    }
    if (!redirect_uri || !oauth.validateRedirectUri(client, redirect_uri as string)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect URI' });
    }

    if (!req.session.user) {
        const authParams = new URLSearchParams({
            response_type: response_type as string,
            client_id: client_id as string,
            redirect_uri: redirect_uri as string,
            scope: (scope as string) || '',
            state: (state as string) || '',
            nonce: (nonce as string) || '',
        });
        const returnTo = `/oauth/authorize?${authParams}`;
        return req.session.save((err) => {
            if (err) return res.status(500).json({ error: 'server_error' });
            return res.redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
        });
    }

    const consentParams = new URLSearchParams({
        client_id: client_id as string,
        redirect_uri: redirect_uri as string,
        scope: (scope as string) || '',
        state: (state as string) || '',
        nonce: (nonce as string) || '',
    });
    return res.redirect(`/consent?${consentParams}`);
});

router.post('/oauth/consent', csrfProtection, requireAuth, async (req: Request, res: Response) => {
    const { client_id, redirect_uri, scopes, approved, state, nonce } = req.body;

    const redirectUrl = new URL(redirect_uri);

    if (approved !== 'true') {
        redirectUrl.searchParams.append('error', 'access_denied');
        redirectUrl.searchParams.append('error_description', 'The user denied the request');
        if (state) redirectUrl.searchParams.append('state', state);
        return res.json({ redirect: redirectUrl.toString() });
    }

    const client = storage.getClient(client_id);
    if (!client) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client' });
    }

    const scopesArray = Array.isArray(scopes) ? scopes : (scopes as string).split(',');
    const authCode = oauth.generateAuthorizationCode(
        client_id,
        req.session.user!.id,
        redirect_uri,
        scopesArray,
        nonce
    );

    redirectUrl.searchParams.append('code', authCode.code);
    if (state) redirectUrl.searchParams.append('state', state);

    return res.json({ redirect: redirectUrl.toString() });
});

router.post('/oauth/token', async (req: Request, res: Response) => {
    const {
        grant_type, code, redirect_uri, client_id, client_secret,
        refresh_token, device_code, username, password, scope
    } = req.body as {
        grant_type: string; code?: string; redirect_uri?: string;
        client_id: string; client_secret: string; refresh_token?: string;
        device_code?: string; username?: string; password?: string; scope?: string;
    };

    const fromHeader = extractBasicAuth(req);
    const finalClientId = client_id || fromHeader.clientId;
    const finalClientSecret = client_secret || fromHeader.clientSecret;

    const client = oauth.validateClient(finalClientId, finalClientSecret);
    if (!client) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
    }

    try {
        if (grant_type === 'authorization_code') {
            if (!code || !redirect_uri) {
                return res.status(400).json({ error: 'invalid_request', error_description: 'Missing required parameters: code and redirect_uri' });
            }
            const authCode = oauth.validateAuthorizationCode(code, finalClientId, redirect_uri);
            if (!authCode) {
                return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid authorization code' });
            }
            const token = await oauth.generateTokens(finalClientId, authCode.userId, authCode.scopes, authCode);
            storage.removeAuthorizationCode(code);
            return res.json(token);
        }

        if (grant_type === 'refresh_token') {
            if (!refresh_token) {
                return res.status(400).json({ error: 'invalid_request', error_description: 'Missing refresh_token parameter' });
            }
            const token = await oauth.refreshToken(refresh_token, finalClientId);
            if (!token) {
                return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid refresh token' });
            }
            return res.json(token);
        }

        if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
            if (!device_code) {
                return res.status(400).json({ error: 'invalid_request', error_description: 'Missing device_code parameter' });
            }
            const result = await oauth.processDeviceCodeTokenRequest(device_code, finalClientId);
            if ('error' in result) return res.status(400).json(result);
            return res.json(result);
        }

        if (grant_type === 'password') {
            if (!username || !password) {
                return res.status(400).json({ error: 'invalid_request', error_description: 'Missing username or password' });
            }
            const loginResult = await easypanel.validateEasypanelCredentials(username, password);
            if (!loginResult.success || !loginResult.user) {
                return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid credentials' });
            }
            const requestedScopes = scope ? scope.split(' ') : ['profile', 'email'];
            const token = await oauth.generateTokens(finalClientId, loginResult.user.id, oauth.filterScopes(client, requestedScopes));
            return res.json(token);
        }

        if (grant_type === 'client_credentials') {
            if (!client.allowedScopes.includes('system')) {
                return res.status(400).json({ error: 'unauthorized_client', error_description: 'This client is not authorized to use client credentials grant' });
            }
            const requestedScopes = scope ? scope.split(' ') : ['system'];
            const validScopes = oauth.filterScopes(client, requestedScopes);
            if (validScopes.length === 0) {
                return res.status(400).json({ error: 'invalid_scope', error_description: 'Requested scopes are not allowed for this client' });
            }
            const token = await oauth.generateTokens(finalClientId, finalClientId, validScopes);
            return res.json(token);
        }

        return res.status(400).json({ error: 'unsupported_grant_type', error_description: `Grant type '${grant_type}' is not supported` });
    } catch (error) {
        console.error('Error processing token request:', error);
        return res.status(500).json({ error: 'server_error', error_description: 'An error occurred while processing the token request' });
    }
});

router.post('/oauth/introspect', async (req: Request, res: Response) => {
    const { token } = req.body as { token: string };
    if (!token) return res.json({ active: false });
    const accessToken = oauth.validateAccessToken(token);
    if (!accessToken) return res.json({ active: false });
    return res.json({
        active: true,
        client_id: accessToken.clientId,
        username: accessToken.userId,
        scope: accessToken.scopes.join(' '),
        exp: Math.floor(accessToken.expiresAt.getTime() / 1000),
    });
});

router.get('/oauth/userinfo', requireApiAuth, async (req: Request, res: Response) => {
    const token = res.locals.token;
    const user = await easypanel.getUserById(API_TOKEN, token.userId);
    if (!user) {
        return res.status(404).json({ error: 'not_found', error_description: 'User not found' });
    }
    const userInfo: Record<string, unknown> = { sub: user.id };
    if (token.scopes.includes('email')) {
        userInfo.email = user.email;
        userInfo.email_verified = true;
    }
    if (token.scopes.includes('profile')) {
        userInfo.name = user.email;
    }
    return res.json(userInfo);
});

export default router;
