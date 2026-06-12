import crypto from 'crypto';
import { Client, AuthorizationCode, Token } from '../types';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { open } from 'lmdb';

const DATA_DIR = path.join(process.cwd(), 'data');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const rootDb = open({
    path: DATA_DIR,
    compression: true,
    maxDbs: 10,
    maxReaders: 126,
    overlappingSync: true
});

const db = {
    clients: rootDb.openDB<Client>({ name: 'clients', encoding: 'json', compression: true }),
    authorizationCodes: rootDb.openDB<AuthorizationCode>({ name: 'authorizationCodes', encoding: 'json', compression: true }),
    tokens: rootDb.openDB<Token>({ name: 'tokens', encoding: 'json', compression: true }),
    refreshTokens: rootDb.openDB<string>({ name: 'refreshTokens', encoding: 'json' }),
    sessions: rootDb.openDB<{ session: unknown; expires: number }>({ name: 'sessions', encoding: 'json', compression: true })
};

export const sessionsDb = db.sessions;

function generateRandomString(length: number): string {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}

export function initializeTestClient(): void {
    if (getClient('test-client')) return;

    const testClient: Client = {
        id: 'test-client',
        name: 'Test Client',
        secret: 'test-secret',
        redirectUris: ['http://localhost:8080/callback'],
        allowedScopes: ['profile', 'email'],
        createdAt: new Date(),
        persistent: true
    };

    db.clients.putSync(testClient.id, testClient);
    console.log(`Test client initialized — ID: ${testClient.id}, Secret: ${testClient.secret}`);
}

export function createClient(
    name: string,
    redirectUris: string[],
    allowedScopes: string[],
    persistent = false
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
    db.clients.putSync(client.id, client);
    return client;
}

export function createClientWithId(
    id: string,
    name: string,
    redirectUris: string[],
    allowedScopes: string[],
    secret: string,
    persistent = false
): Client {
    const client: Client = { id, name, secret, redirectUris, allowedScopes, createdAt: new Date(), persistent };
    db.clients.putSync(client.id, client);
    return client;
}

export function getClient(id: string): Client | undefined {
    return db.clients.get(id);
}

export function listClients(): Client[] {
    const clients: Client[] = [];
    for (const { value } of db.clients.getRange()) clients.push(value);
    return clients;
}

export function deleteClient(id: string): boolean {
    try {
        return db.clients.removeSync(id);
    } catch {
        return false;
    }
}

export function updateClient(id: string, updates: Partial<Omit<Client, 'createdAt'>>): Client | null {
    const client = getClient(id);
    if (!client) return null;

    if (updates.id && updates.id !== id) {
        const updatedClient = { ...client, ...updates, createdAt: client.createdAt };
        db.clients.removeSync(id);
        db.clients.putSync(updatedClient.id, updatedClient);
        return updatedClient;
    }

    const updatedClient = { ...client, ...updates, id: client.id, createdAt: client.createdAt };
    db.clients.putSync(id, updatedClient);
    return updatedClient;
}

export function storeAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scopes: string[],
    expiresIn: number,
    nonce?: string
): AuthorizationCode {
    const code = generateRandomString(32);
    const authCode: AuthorizationCode = {
        code,
        clientId,
        userId,
        redirectUri,
        scopes,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        nonce
    };
    db.authorizationCodes.putSync(code, authCode);
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

export function storeToken(clientId: string, userId: string, scopes: string[], expiresIn: number): Token {
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

export function cleanupExpiredItems(): void {
    const now = new Date();
    for (const { key, value } of db.authorizationCodes.getRange()) {
        if (value.expiresAt < now) db.authorizationCodes.removeSync(key);
    }
    for (const { key, value } of db.tokens.getRange()) {
        if (value.expiresAt < now) {
            db.refreshTokens.removeSync(value.refreshToken);
            db.tokens.removeSync(key);
        }
    }
    const nowMs = Date.now();
    for (const { key, value } of db.sessions.getRange()) {
        if (value.expires < nowMs) db.sessions.removeSync(key);
    }
}

setInterval(cleanupExpiredItems, 60 * 60 * 1000);
