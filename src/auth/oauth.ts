import crypto from 'crypto';
import {
    AuthorizationCode,
    Token,
    Client
} from '../types';
import {
    ACCESS_TOKEN_EXPIRY,
    REFRESH_TOKEN_EXPIRY,
    AUTH_CODE_EXPIRY
} from '../config';
import * as storage from '../storage/memory';
import * as deviceStorage from '../storage/device';
import { DeviceCodeStatus } from '../storage/device';

/**
 * Generates an authorization code
 */
export function generateAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scopes: string[]
): AuthorizationCode {
    return storage.storeAuthorizationCode(
        clientId,
        userId,
        redirectUri,
        scopes,
        AUTH_CODE_EXPIRY
    );
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
 * Generates tokens from an authorization code
 */
export function generateTokens(
    clientId: string,
    userId: string,
    scopes: string[]
): Token {
    return storage.storeToken(
        clientId,
        userId,
        scopes,
        ACCESS_TOKEN_EXPIRY
    );
}

/**
 * Refreshes an access token
 */
export function refreshToken(refreshToken: string, clientId: string): Token | null {
    const oldToken = storage.getTokenByRefreshToken(refreshToken);

    if (!oldToken || oldToken.clientId !== clientId) {
        return null;
    }

    // Generate new tokens
    const newToken = storage.storeToken(
        oldToken.clientId,
        oldToken.userId,
        oldToken.scopes,
        ACCESS_TOKEN_EXPIRY
    );

    // Remove old token
    if (oldToken.accessToken) {
        storage.removeToken(oldToken.accessToken);
    }

    return newToken;
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
    return requestedScopes.filter(scope => client.allowedScopes.includes(scope));
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
export function processDeviceCodeTokenRequest(
    deviceCode: string,
    clientId: string
): Token | DeviceCodeError {
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
    return storage.storeToken(
        deviceAuth.clientId,
        deviceAuth.userId!,
        deviceAuth.scopes,
        ACCESS_TOKEN_EXPIRY
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