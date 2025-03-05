import { Client, AuthorizationCode, Token } from '../types';
import { v4 as uuidv4 } from 'uuid';

// In-memory storage (should be replaced with a database in production)
export const clients: Map<string, Client> = new Map();
export const authorizationCodes: Map<string, AuthorizationCode> = new Map();
export const tokens: Map<string, Token> = new Map();
export const refreshTokens: Map<string, string> = new Map(); // Maps refresh token to access token

// Create a test client by default
export function initializeTestClient(): void {
    const testClient: Client = {
        id: 'test-client',
        name: 'Test Client',
        secret: 'test-secret',
        redirectUris: ['http://localhost:8080/callback'],
        allowedScopes: ['profile', 'email'],
        createdAt: new Date(),
    };
    clients.set(testClient.id, testClient);

    console.log('Test client initialized:');
    console.log(`- Client ID: ${testClient.id}`);
    console.log(`- Client Secret: ${testClient.secret}`);
    console.log(`- Redirect URIs: ${testClient.redirectUris.join(', ')}`);
}

// Client CRUD operations
export function createClient(name: string, redirectUris: string[], allowedScopes: string[]): Client {
    const client: Client = {
        id: uuidv4(),
        name,
        secret: generateRandomString(32),
        redirectUris,
        allowedScopes,
        createdAt: new Date(),
    };
    clients.set(client.id, client);
    return client;
}

export function getClient(id: string): Client | undefined {
    return clients.get(id);
}

export function listClients(): Client[] {
    return Array.from(clients.values());
}

export function deleteClient(id: string): boolean {
    return clients.delete(id);
}

// Authorization code operations
export function storeAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scopes: string[],
    expiresIn: number
): AuthorizationCode {
    const code = generateRandomString(32);
    const authCode: AuthorizationCode = {
        code,
        clientId,
        userId,
        redirectUri,
        scopes,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
    };
    authorizationCodes.set(code, authCode);
    return authCode;
}

export function getAuthorizationCode(code: string): AuthorizationCode | undefined {
    return authorizationCodes.get(code);
}

export function removeAuthorizationCode(code: string): boolean {
    return authorizationCodes.delete(code);
}

// Token operations
export function storeToken(
    clientId: string,
    userId: string,
    scopes: string[],
    expiresIn: number
): Token {
    const accessToken = generateRandomString(64);
    const refreshToken = generateRandomString(64);

    const token: Token = {
        accessToken,
        refreshToken,
        clientId,
        userId,
        scopes,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
    };

    tokens.set(accessToken, token);
    refreshTokens.set(refreshToken, accessToken);

    return token;
}

export function getToken(accessToken: string): Token | undefined {
    return tokens.get(accessToken);
}

export function getTokenByRefreshToken(refreshToken: string): Token | undefined {
    const accessToken = refreshTokens.get(refreshToken);
    if (!accessToken) return undefined;

    return tokens.get(accessToken);
}

export function removeToken(accessToken: string): boolean {
    const token = tokens.get(accessToken);
    if (!token) return false;

    refreshTokens.delete(token.refreshToken);
    return tokens.delete(accessToken);
}

// Helper function to generate random strings
function generateRandomString(length: number): string {
    return Array.from(
        { length },
        () => Math.floor(Math.random() * 36).toString(36)
    ).join('');
}