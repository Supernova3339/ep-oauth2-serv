import { Client, AuthorizationCode, Token } from '../types';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';

// File storage paths
const DATA_DIR = path.join(process.cwd(), 'data');
const CLIENTS_FILE = path.join(DATA_DIR, 'clients.json');

// In-memory storage ( I don't want to do a database for this )
export const clients: Map<string, Client> = new Map();
export const authorizationCodes: Map<string, AuthorizationCode> = new Map();
export const tokens: Map<string, Token> = new Map();
export const refreshTokens: Map<string, string> = new Map(); // Maps refresh token to access token

// Ensure data directory exists
function ensureDataDirectory() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }
}

// Save clients to file
function saveClientsToFile() {
    ensureDataDirectory();
    const clientsArray = Array.from(clients.values());
    fs.writeFileSync(CLIENTS_FILE, JSON.stringify(clientsArray, null, 2));
    console.log(`Saved ${clientsArray.length} clients to ${CLIENTS_FILE}`);
}

// Load clients from file
function loadClientsFromFile() {
    ensureDataDirectory();

    if (!fs.existsSync(CLIENTS_FILE)) {
        console.log(`Clients file not found at ${CLIENTS_FILE}`);
        return;
    }

    try {
        const data = fs.readFileSync(CLIENTS_FILE, 'utf8');
        const clientsArray = JSON.parse(data) as Client[];

        clientsArray.forEach(client => {
            // Convert string dates back to Date objects
            client.createdAt = new Date(client.createdAt);
            clients.set(client.id, client);
        });

        console.log(`Loaded ${clientsArray.length} clients from ${CLIENTS_FILE}`);
    } catch (error) {
        console.error('Error loading clients from file:', error);
    }
}

// Create a test client by default
export function initializeTestClient(): void {
    // First load any existing clients
    loadClientsFromFile();

    // Check if test client already exists
    if (clients.has('test-client')) {
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
    clients.set(testClient.id, testClient);

    // Save to file since it's persistent
    saveClientsToFile();

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
    clients.set(client.id, client);

    // Save to file if it's a persistent client
    if (persistent) {
        saveClientsToFile();
    }

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
    clients.set(client.id, client);

    // Save to file if it's a persistent client
    if (persistent) {
        saveClientsToFile();
    }

    return client;
}

export function getClient(id: string): Client | undefined {
    return clients.get(id);
}

export function listClients(): Client[] {
    return Array.from(clients.values());
}

export function deleteClient(id: string): boolean {
    const client = clients.get(id);
    if (!client) return false;

    const result = clients.delete(id);

    // Update the file if client was persistent
    if (result && client.persistent) {
        saveClientsToFile();
    }

    return result;
}

export function updateClient(
    id: string,
    updates: Partial<Omit<Client, 'createdAt'>>
): Client | null {
    const client = clients.get(id);
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
        clients.delete(id);

        // Add the new client with the new ID
        clients.set(updatedClient.id, updatedClient);

        // Save to file if it's a persistent client
        if (updatedClient.persistent) {
            saveClientsToFile();
        }

        return updatedClient;
    }

    // Regular update without changing the ID
    const updatedClient = {
        ...client,
        ...updates,
        id: client.id, // Ensure ID doesn't change in this branch
        createdAt: client.createdAt // Ensure this can't be changed
    };

    clients.set(id, updatedClient);

    // Save to file if it's a persistent client
    if (updatedClient.persistent) {
        saveClientsToFile();
    }

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
    authorizationCodes.set(code, authCode);

    console.log(`Stored authorization code ${code} for client ${clientId} and user ${userId}`);
    console.log(`Auth code will expire at ${authCode.expiresAt}`);

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