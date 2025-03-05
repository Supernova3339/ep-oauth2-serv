import crypto from 'crypto';
import * as jose from 'jose';
import {
    AuthorizationCode,
    Token,
    Client,
    EasypanelUser
} from '../types';
import {
    ACCESS_TOKEN_EXPIRY,
    REFRESH_TOKEN_EXPIRY,
    AUTH_CODE_EXPIRY
} from '../config';
import * as storage from '../storage/memory';
import * as deviceStorage from '../storage/device';
import { DeviceCodeStatus } from '../storage/device';
import * as easypanel from '../auth/easypanel';

// Generate RSA key pair for signing JWTs
// In production, this should be loaded from secure storage
let privateKey: jose.KeyLike | null = null;
let publicKey: jose.KeyLike | null = null;

// Initialize keys
async function initKeys() {
    if (!privateKey || !publicKey) {
        // Generate a new RSA key pair
        const { privateKey: privKey, publicKey: pubKey } = await jose.generateKeyPair('RS256');
        privateKey = privKey;
        publicKey = pubKey;

        // In production, you would save these keys securely
        console.log('Generated new RSA key pair for JWT signing');
    }
}

// Initialize keys when this module is loaded
initKeys().catch(err => {
    console.error('Failed to initialize JWT keys:', err);
    process.exit(1);
});

// Export the public key for JWKS endpoint
export async function getPublicJwk(): Promise<jose.JWK> {
    if (!publicKey) {
        await initKeys();
    }

    // Convert the public key to JWK format
    const jwk = await jose.exportJWK(publicKey!);

    // Add key ID and use
    return {
        ...jwk,
        kid: 'oauth-server-key-1',
        use: 'sig',
        alg: 'RS256'
    };
}

/**
 * Generates an authorization code
 */
export function generateAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scopes: string[],
    nonce?: string
): AuthorizationCode {
    const authCode = storage.storeAuthorizationCode(
        clientId,
        userId,
        redirectUri,
        scopes,
        AUTH_CODE_EXPIRY,
        nonce
    );

    return authCode;
}

/**
 * Validates an authorization code
 */
export function validateAuthorizationCode(
    code: string,
    clientId: string,
    redirectUri: string
): AuthorizationCode | null {
    const authCode = storage.getAuthorizationCode(code);

    if (!authCode) {
        return null;
    }

    // Check if code is valid for this client and redirect URI
    if (authCode.clientId !== clientId ||
        authCode.redirectUri !== redirectUri ||
        authCode.expiresAt < new Date()) {
        return null;
    }

    return authCode;
}

/**
 * Generates tokens including OpenID Connect ID token if needed
 */
export async function generateTokens(
    clientId: string,
    userId: string,
    scopes: string[],
    authCode?: AuthorizationCode
): Promise<TokenResponse> {
    // Generate basic token (access and refresh)
    const token = storage.storeToken(
        clientId,
        userId,
        scopes,
        ACCESS_TOKEN_EXPIRY
    );

    // Check if this is an OpenID Connect request
    const isOpenIdConnect = scopes.includes('openid');
    let idToken = undefined;

    if (isOpenIdConnect) {
        try {
            // Get user information for claims
            const user = await easypanel.getUserById('admin-token', userId);

            if (user) {
                // Generate ID token
                idToken = await generateIdToken(
                    clientId,
                    userId,
                    scopes,
                    user,
                    authCode?.nonce
                );
            }
        } catch (error) {
            console.error('Error generating ID token:', error);
        }
    }

    return {
        access_token: token.accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_EXPIRY,
        refresh_token: token.refreshToken,
        scope: scopes.join(' '),
        id_token: idToken
    };
}

/**
 * Generate an OpenID Connect ID token
 */
async function generateIdToken(
    clientId: string,
    userId: string,
    scopes: string[],
    user: EasypanelUser,
    nonce?: string
): Promise<string> {
    if (!privateKey) {
        await initKeys();
    }

    // Current time in seconds
    const now = Math.floor(Date.now() / 1000);

    // Build claims based on scopes
    const claims: Record<string, any> = {
        // Required claims
        iss: `http://localhost:3000`, // Issuer URL (should be configurable)
        sub: userId,                   // Subject (user ID)
        aud: clientId,                 // Audience (client ID)
        exp: now + ACCESS_TOKEN_EXPIRY, // Expiration time
        iat: now,                      // Issued at time
    };

    // Add nonce if provided (for replay prevention)
    if (nonce) {
        claims.nonce = nonce;
    }

    // Add profile claims if scope includes 'profile'
    if (scopes.includes('profile')) {
        claims.name = user.email; // Using email as name since we don't have a separate name field
        // Add other profile claims as available
    }

    // Add email claims if scope includes 'email'
    if (scopes.includes('email')) {
        claims.email = user.email;
        claims.email_verified = true; // Assuming emails are verified
    }

    // Generate the JWT
    const jwt = await new jose.SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'oauth-server-key-1' })
        .sign(privateKey!);

    return jwt;
}

/**
 * Refreshes an access token
 */
export async function refreshToken(refreshToken: string, clientId: string): Promise<TokenResponse | null> {
    const oldToken = storage.getTokenByRefreshToken(refreshToken);

    if (!oldToken || oldToken.clientId !== clientId) {
        return null;
    }

    // Generate new tokens
    const response = await generateTokens(
        oldToken.clientId,
        oldToken.userId,
        oldToken.scopes
    );

    // Remove old token
    if (oldToken.accessToken) {
        storage.removeToken(oldToken.accessToken);
    }

    return response;
}

/**
 * Validates an access token
 */
export function validateAccessToken(token: string): Token | null {
    const accessToken = storage.getToken(token);

    if (!accessToken || accessToken.expiresAt < new Date()) {
        return null;
    }

    return accessToken;
}

/**
 * Validates client credentials
 */
export function validateClient(clientId: string, clientSecret: string): Client | null {
    const client = storage.getClient(clientId);

    if (!client || client.secret !== clientSecret) {
        return null;
    }

    return client;
}

/**
 * Validates redirect URI for a client
 */
export function validateRedirectUri(client: Client, redirectUri: string): boolean {
    return client.redirectUris.includes(redirectUri);
}

/**
 * Filters scopes based on what's allowed for the client
 */
export function filterScopes(client: Client, requestedScopes: string[]): string[] {
    // For OpenID Connect, we need to ensure 'openid' scope is included
    // when other openid-related scopes are requested
    if (requestedScopes.includes('profile') || requestedScopes.includes('email')) {
        if (!requestedScopes.includes('openid')) {
            requestedScopes.push('openid');
        }
    }

    // Filter scopes based on what's allowed for the client
    return requestedScopes.filter(scope => {
        // If the client is specifically allowed this scope
        if (client.allowedScopes.includes(scope)) {
            return true;
        }

        // Special case: if client allows 'openid' scope, implicitly allow 'profile' and 'email'
        if ((scope === 'profile' || scope === 'email') && client.allowedScopes.includes('openid')) {
            return true;
        }

        return false;
    });
}

/**
 * Generates a random token
 */
export function generateRandomToken(length = 32): string {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Creates a device authorization
 */
export function createDeviceAuthorization(
    clientId: string,
    scopes: string[],
    verificationUri: string
): DeviceAuthResponse {
    // Validate scopes for this client
    const client = storage.getClient(clientId);
    if (!client) {
        throw new Error('Invalid client_id');
    }

    const validScopes = filterScopes(client, scopes);

    // Create device code
    const deviceData = deviceStorage.createDeviceCode(clientId, validScopes, verificationUri);

    return {
        device_code: deviceData.deviceCode,
        user_code: deviceData.userCode,
        verification_uri: deviceData.verificationUri,
        verification_uri_complete: deviceData.verificationUriComplete,
        expires_in: Math.floor((deviceData.expiresAt.getTime() - Date.now()) / 1000),
        interval: deviceData.interval
    };
}

/**
 * Get a device authorization by device code
 */
export function getDeviceAuthorization(deviceCode: string): DeviceAuthorization | null {
    const deviceData = deviceStorage.getDeviceCode(deviceCode);
    if (!deviceData) {
        return null;
    }

    return {
        deviceCode: deviceData.deviceCode,
        clientId: deviceData.clientId,
        scopes: deviceData.scopes,
        userId: deviceData.userId,
        status: deviceData.status,
        expiresAt: deviceData.expiresAt
    };
}

/**
 * Process token request for device authorization grant
 */
export async function processDeviceCodeTokenRequest(
    deviceCode: string,
    clientId: string
): Promise<TokenResponse | DeviceCodeError> {
    const deviceAuth = deviceStorage.getDeviceCode(deviceCode);

    // Check if device code exists
    if (!deviceAuth) {
        return { error: 'invalid_grant', error_description: 'Invalid device code' };
    }

    // Check if device code is for this client
    if (deviceAuth.clientId !== clientId) {
        return { error: 'invalid_grant', error_description: 'Device code was not issued to this client' };
    }

    // Check expiration
    if (deviceAuth.expiresAt < new Date()) {
        return { error: 'expired_token', error_description: 'Device code has expired' };
    }

    // Check status
    if (deviceAuth.status === DeviceCodeStatus.PENDING) {
        return { error: 'authorization_pending', error_description: 'The authorization request is still pending' };
    } else if (deviceAuth.status === DeviceCodeStatus.DENIED) {
        return { error: 'access_denied', error_description: 'The user denied the authorization request' };
    } else if (deviceAuth.status === DeviceCodeStatus.EXPIRED) {
        return { error: 'expired_token', error_description: 'Device code has expired' };
    } else if (deviceAuth.status === DeviceCodeStatus.USED) {
        return { error: 'invalid_grant', error_description: 'Device code has already been used' };
    }

    // If authorized, must have userId
    if (deviceAuth.status === DeviceCodeStatus.AUTHORIZED && !deviceAuth.userId) {
        return { error: 'server_error', error_description: 'Invalid device code state' };
    }

    // Mark code as used
    const marked = deviceStorage.useDeviceCode(deviceCode);
    if (!marked) {
        return { error: 'server_error', error_description: 'Failed to mark device code as used' };
    }

    // Generate tokens
    return await generateTokens(
        deviceAuth.clientId,
        deviceAuth.userId!,
        deviceAuth.scopes
    );
}

// Response types
export interface DeviceAuthResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
}

export interface DeviceCodeError {
    error: string;
    error_description: string;
}

export interface DeviceAuthorization {
    deviceCode: string;
    clientId: string;
    scopes: string[];
    userId?: string;
    status: DeviceCodeStatus;
    expiresAt: Date;
}

export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    scope: string;
    id_token?: string; // OpenID Connect ID token
}