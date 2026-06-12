import crypto from 'crypto';
import * as jose from 'jose';
import { AuthorizationCode, Token, Client, EasypanelUser } from '../types';
import { ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY, AUTH_CODE_EXPIRY, API_TOKEN, ISSUER_URL } from '../config';
import * as storage from '../storage/lmdb';
import * as deviceStorage from '../storage/device-lmdb';
import { DeviceCodeStatus } from '../storage/device-lmdb';
import * as easypanel from '../auth/easypanel';

let privateKey: jose.KeyLike | null = null;
let publicKey: jose.KeyLike | null = null;

async function initKeys() {
    if (!privateKey || !publicKey) {
        const { privateKey: privKey, publicKey: pubKey } = await jose.generateKeyPair('RS256');
        privateKey = privKey;
        publicKey = pubKey;
    }
}

initKeys().catch(err => {
    console.error('Failed to initialize JWT keys:', err);
    process.exit(1);
});

export async function getPublicJwk(): Promise<jose.JWK> {
    if (!publicKey) await initKeys();
    return {
        ...(await jose.exportJWK(publicKey!)),
        kid: 'oauth-server-key-1',
        use: 'sig',
        alg: 'RS256'
    };
}

export function generateAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scopes: string[],
    nonce?: string
): AuthorizationCode {
    return storage.storeAuthorizationCode(clientId, userId, redirectUri, scopes, AUTH_CODE_EXPIRY, nonce);
}

export function validateAuthorizationCode(
    code: string,
    clientId: string,
    redirectUri: string
): AuthorizationCode | null {
    const authCode = storage.getAuthorizationCode(code);
    if (!authCode) return null;

    if (authCode.clientId !== clientId ||
        authCode.redirectUri !== redirectUri ||
        authCode.expiresAt < new Date()) {
        return null;
    }

    return authCode;
}

export async function generateTokens(
    clientId: string,
    userId: string,
    scopes: string[],
    authCode?: AuthorizationCode
): Promise<TokenResponse> {
    const token = storage.storeToken(clientId, userId, scopes, ACCESS_TOKEN_EXPIRY);

    let idToken: string | undefined;
    if (scopes.includes('openid')) {
        try {
            const user = await easypanel.getUserById(API_TOKEN, userId);
            if (user) {
                idToken = await generateIdToken(clientId, userId, scopes, user, authCode?.nonce);
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

async function generateIdToken(
    clientId: string,
    userId: string,
    scopes: string[],
    user: EasypanelUser,
    nonce?: string
): Promise<string> {
    if (!privateKey) await initKeys();

    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
        iss: ISSUER_URL,
        sub: userId,
        aud: clientId,
        exp: now + ACCESS_TOKEN_EXPIRY,
        iat: now,
    };

    if (nonce) claims.nonce = nonce;
    if (scopes.includes('profile')) claims.name = user.email;
    if (scopes.includes('email')) {
        claims.email = user.email;
        claims.email_verified = true;
    }

    return new jose.SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'oauth-server-key-1' })
        .sign(privateKey!);
}

export async function refreshToken(refreshToken: string, clientId: string): Promise<TokenResponse | null> {
    const oldToken = storage.getTokenByRefreshToken(refreshToken);
    if (!oldToken || oldToken.clientId !== clientId) return null;

    const response = await generateTokens(oldToken.clientId, oldToken.userId, oldToken.scopes);
    storage.removeToken(oldToken.accessToken);
    return response;
}

export function validateAccessToken(token: string): Token | null {
    const accessToken = storage.getToken(token);
    if (!accessToken || accessToken.expiresAt < new Date()) return null;
    return accessToken;
}

export function validateClient(clientId: string, clientSecret: string): Client | null {
    const client = storage.getClient(clientId);
    if (!client || client.secret !== clientSecret) return null;
    return client;
}

export function validateRedirectUri(client: Client, redirectUri: string): boolean {
    return client.redirectUris.includes(redirectUri);
}

export function filterScopes(client: Client, requestedScopes: string[]): string[] {
    if ((requestedScopes.includes('profile') || requestedScopes.includes('email')) &&
        !requestedScopes.includes('openid')) {
        requestedScopes.push('openid');
    }

    return requestedScopes.filter(scope => {
        if (client.allowedScopes.includes(scope)) return true;
        if ((scope === 'profile' || scope === 'email') && client.allowedScopes.includes('openid')) return true;
        return false;
    });
}

export function generateRandomToken(length = 32): string {
    return crypto.randomBytes(length).toString('hex');
}

export function createDeviceAuthorization(
    clientId: string,
    scopes: string[],
    verificationUri: string
): DeviceAuthResponse {
    const client = storage.getClient(clientId);
    if (!client) throw new Error('Invalid client_id');

    const validScopes = filterScopes(client, scopes);
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

export function getDeviceAuthorization(deviceCode: string): DeviceAuthorization | null {
    const deviceData = deviceStorage.getDeviceCode(deviceCode);
    if (!deviceData) return null;

    return {
        deviceCode: deviceData.deviceCode,
        clientId: deviceData.clientId,
        scopes: deviceData.scopes,
        userId: deviceData.userId,
        status: deviceData.status,
        expiresAt: deviceData.expiresAt
    };
}

export async function processDeviceCodeTokenRequest(
    deviceCode: string,
    clientId: string
): Promise<TokenResponse | DeviceCodeError> {
    const deviceAuth = deviceStorage.getDeviceCode(deviceCode);

    if (!deviceAuth) return { error: 'invalid_grant', error_description: 'Invalid device code' };
    if (deviceAuth.clientId !== clientId) return { error: 'invalid_grant', error_description: 'Device code was not issued to this client' };
    if (deviceAuth.expiresAt < new Date()) return { error: 'expired_token', error_description: 'Device code has expired' };

    if (deviceAuth.status === DeviceCodeStatus.PENDING) return { error: 'authorization_pending', error_description: 'The authorization request is still pending' };
    if (deviceAuth.status === DeviceCodeStatus.DENIED) return { error: 'access_denied', error_description: 'The user denied the authorization request' };
    if (deviceAuth.status === DeviceCodeStatus.EXPIRED) return { error: 'expired_token', error_description: 'Device code has expired' };
    if (deviceAuth.status === DeviceCodeStatus.USED) return { error: 'invalid_grant', error_description: 'Device code has already been used' };
    if (deviceAuth.status === DeviceCodeStatus.AUTHORIZED && !deviceAuth.userId) return { error: 'server_error', error_description: 'Invalid device code state' };

    if (!deviceStorage.useDeviceCode(deviceCode)) return { error: 'server_error', error_description: 'Failed to mark device code as used' };

    return generateTokens(deviceAuth.clientId, deviceAuth.userId!, deviceAuth.scopes);
}

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
    id_token?: string;
}
