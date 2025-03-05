import { Client, AuthorizationCode, Token } from '../types';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { open, RootDatabase } from 'lmdb';

// Define a single data directory and file for LMDB
const DATA_DIR = path.join(process.cwd(), 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.mdb');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Create a single LMDB environment
const rootDb = open({
    path: DATA_DIR,
    compression: true,
    // These options help with performance and data integrity
    maxDbs: 10,
    maxReaders: 126,  // Default max value
    overlappingSync: true
});

// Create named databases within the single environment
const db = {
    clients: rootDb.openDB<Client>({
        name: 'clients',
        encoding: 'json',
        compression: true
    }),
    authorizationCodes: rootDb.openDB<AuthorizationCode>({
        name: 'authorizationCodes',
        encoding: 'json',
        compression: true
    }),
    tokens: rootDb.openDB<Token>({
        name: 'tokens',
        encoding: 'json',
        compression: true
    }),
    refreshTokens: rootDb.openDB<string>({
        name: 'refreshTokens',
        encoding: 'json'
    })
};

// Create a test client by default
export function initializeTestClient(): void {
    // Check if test client already exists
    const existingClient = getClient('test-client');

    if (existingClient) {
        console.log('Test client already exists');
        return;
    }

    const testClient: Client = {
        id: 'test-client',
        name: 'Test Client',
        secret: 'test-secret',
        redirectUris: ['http://localhost:8080/callback'],
        allowedScopes: ['profile', 'email'],
        createdAt: new Date(),
        persistent: true
    };

    // Store the client
    db.clients.putSync(testClient.id, testClient);

    console.log('Test client initialized:');
    console.log(`- Client ID: ${testClient.id}`);
    console.log(`- Client Secret: ${testClient.secret}`);
    console.log(`- Redirect URIs: ${testClient.redirectUris.join(', ')}`);
}

// Client CRUD operations
export function createClient(
    name: string,
    redirectUris: string[],
    allowedScopes: string[],
    persistent: boolean = false
): Client {
    const client: Client = {
        id: uuidv4(),
        name,
        secret: generateRandomString(32),
        redirectUris,
        allowedScopes,
        createdAt: new Date(),
        persistent
    };

    // Store the client
    db.clients.putSync(client.id, client);

    return client;
}

/**
 * Creates a client with a specific ID
 */
export function createClientWithId(
    id: string,
    name: string,
    redirectUris: string[],
    allowedScopes: string[],
    secret: string,
    persistent: boolean = false
): Client {
    const client: Client = {
        id,
        name,
        secret,
        redirectUris,
        allowedScopes,
        createdAt: new Date(),
        persistent
    };

    // Store the client
    db.clients.putSync(client.id, client);

    return client;
}

export function getClient(id: string): Client | undefined {
    return db.clients.get(id);
}

export function listClients(): Client[] {
    const clients: Client[] = [];
    for (const { value } of db.clients.getRange()) {
        clients.push(value);
    }
    return clients;
}

export function deleteClient(id: string): boolean {
    try {
        // LMDB.remove returns a Promise<boolean>, but our API expects synchronous behavior
        // Use removeSync instead of remove to maintain the API
        return db.clients.removeSync(id);
    } catch {
        return false;
    }
}

export function updateClient(
    id: string,
    updates: Partial<Omit<Client, 'createdAt'>>
): Client | null {
    const client = getClient(id);
    if (!client) return null;

    // If we're trying to update the ID, handle it specially
    if (updates.id && updates.id !== id) {
        // Create a new client with the updated ID
        const updatedClient = {
            ...client,
            ...updates,
            createdAt: client.createdAt
        };

        // Remove the old client
        db.clients.removeSync(id);

        // Add the new client with the new ID
        db.clients.putSync(updatedClient.id, updatedClient);

        return updatedClient;
    }

    // Regular update without changing the ID
    const updatedClient = {
        ...client,
        ...updates,
        id: client.id, // Ensure ID doesn't change in this branch
        createdAt: client.createdAt // Ensure this can't be changed
    };

    db.clients.putSync(id, updatedClient);

    return updatedClient;
}

// Authorization code operations
export function storeAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scopes: string[],
    expiresIn: number,
    nonce?: string // Add nonce parameter
): AuthorizationCode {
    const code = generateRandomString(32);
    const authCode: AuthorizationCode = {
        code,
        clientId,
        userId,
        redirectUri,
        scopes,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        nonce // Store the nonce if provided
    };

    db.authorizationCodes.putSync(code, authCode);

    console.log(`Stored authorization code ${code} for client ${clientId} and user ${userId}`);
    console.log(`Auth code will expire at ${authCode.expiresAt}`);

    return authCode;
}

export function getAuthorizationCode(code: string): AuthorizationCode | undefined {
    return db.authorizationCodes.get(code);
}

export function removeAuthorizationCode(code: string): boolean {
    try {
        return db.authorizationCodes.removeSync(code);
    } catch {
        return false;
    }
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

    db.tokens.putSync(accessToken, token);
    db.refreshTokens.putSync(refreshToken, accessToken);

    return token;
}

export function getToken(accessToken: string): Token | undefined {
    return db.tokens.get(accessToken);
}

export function getTokenByRefreshToken(refreshToken: string): Token | undefined {
    const accessToken = db.refreshTokens.get(refreshToken);
    if (!accessToken) return undefined;

    return db.tokens.get(accessToken);
}

export function removeToken(accessToken: string): boolean {
    try {
        const token = db.tokens.get(accessToken);
        if (!token) return false;

        db.refreshTokens.removeSync(token.refreshToken);
        return db.tokens.removeSync(accessToken);
    } catch {
        return false;
    }
}

// Helper function to generate random strings
function generateRandomString(length: number): string {
    return Array.from(
        { length },
        () => Math.floor(Math.random() * 36).toString(36)
    ).join('');
}

// Cleanup function to remove expired items
export function cleanupExpiredItems(): void {
    const now = new Date();

    // Cleanup expired authorization codes
    for (const { key, value } of db.authorizationCodes.getRange()) {
        if (value.expiresAt < now) {
            db.authorizationCodes.removeSync(key);
        }
    }

    // Cleanup expired tokens
    for (const { key, value } of db.tokens.getRange()) {
        if (value.expiresAt < now) {
            db.refreshTokens.removeSync(value.refreshToken);
            db.tokens.removeSync(key);
        }
    }
}

// Run cleanup every hour
setInterval(cleanupExpiredItems, 60 * 60 * 1000);