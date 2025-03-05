#!/usr/bin/env ts-node

/**
 * Client Management Example for Easypanel OAuth2 Server
 *
 * This script demonstrates how to create, list, update, and delete OAuth clients,
 * including the ability to make them persistent.
 *
 * Usage:
 *   ts-node client-management.ts
 */

import * as storage from '../src/storage/memory';
import { Client } from '../src/types';

async function main() {
    console.log('OAuth2 Client Management Example\n');

    // Initialize storage
    storage.initializeTestClient();

    // List existing clients
    console.log('Existing clients:');
    listAllClients();

    // Create a new persistent client
    console.log('\nCreating a new persistent client...');
    const mobileApp = createPersistentClient(
        'Mobile App',
        ['com.example.app://callback'],
        ['profile', 'email', 'openid']
    );
    console.log('Created new client:');
    console.log(`- Client ID: ${mobileApp.id}`);
    console.log(`- Client Secret: ${mobileApp.secret}`);
    console.log(`- Redirect URIs: ${mobileApp.redirectUris.join(', ')}`);
    console.log(`- Persistent: ${mobileApp.persistent}`);

    // Create a non-persistent client (for comparison)
    console.log('\nCreating a non-persistent client...');
    const tempClient = createNonPersistentClient(
        'Temporary Client',
        ['http://localhost:3001/callback'],
        ['profile']
    );
    console.log('Created temporary client:');
    console.log(`- Client ID: ${tempClient.id}`);
    console.log(`- Client Secret: ${tempClient.secret}`);
    console.log(`- Redirect URIs: ${tempClient.redirectUris.join(', ')}`);
    console.log(`- Persistent: ${tempClient.persistent}`);

    // List all clients after creation
    console.log('\nClients after creation:');
    listAllClients();

    // Update the mobile app client
    console.log('\nUpdating mobile app client...');
    const updatedMobileApp = updateClient(
        mobileApp.id,
        {
            name: 'Updated Mobile App',
            redirectUris: [...mobileApp.redirectUris, 'com.example.app://login-callback'],
            allowedScopes: [...mobileApp.allowedScopes, 'offline_access']
        }
    );

    if (updatedMobileApp) {
        console.log('Updated client:');
        console.log(`- Client ID: ${updatedMobileApp.id}`);
        console.log(`- Name: ${updatedMobileApp.name}`);
        console.log(`- Redirect URIs: ${updatedMobileApp.redirectUris.join(', ')}`);
        console.log(`- Allowed Scopes: ${updatedMobileApp.allowedScopes.join(', ')}`);
    }

    // Delete the temporary client
    console.log('\nDeleting temporary client...');
    const tempDeleted = deleteClient(tempClient.id);
    console.log(`Temporary client deleted: ${tempDeleted}`);

    // List clients after deletion
    console.log('\nClients after deletion:');
    listAllClients();

    // Restart the process to verify persistence
    console.log('\nSimulating restart to verify persistence...');
    simulateRestart();

    // List clients after "restart"
    console.log('\nClients after restart:');
    listAllClients();
}

// Helper functions
function listAllClients() {
    const clients = storage.listClients();
    if (clients.length === 0) {
        console.log('No clients found.');
        return;
    }

    clients.forEach((client, index) => {
        console.log(`${index + 1}. ${client.name} (${client.id})`);
        console.log(`   - Redirect URIs: ${client.redirectUris.join(', ')}`);
        console.log(`   - Scopes: ${client.allowedScopes.join(', ')}`);
        console.log(`   - Persistent: ${client.persistent}`);
    });
}

function createPersistentClient(name: string, redirectUris: string[], allowedScopes: string[]): Client {
    return storage.createClient(name, redirectUris, allowedScopes, true);
}

function createNonPersistentClient(name: string, redirectUris: string[], allowedScopes: string[]): Client {
    return storage.createClient(name, redirectUris, allowedScopes, false);
}

function updateClient(id: string, updates: Partial<Client>): Client | null {
    return storage.updateClient(id, updates);
}

function deleteClient(id: string): boolean {
    return storage.deleteClient(id);
}

// Simulate a server restart by re-initializing the storage
function simulateRestart() {
    // Clear in-memory storage
    storage.clients.clear();
    storage.authorizationCodes.clear();
    storage.tokens.clear();
    storage.refreshTokens.clear();

    // Re-initialize (will load from file)
    storage.initializeTestClient();
}

// Run the main function
main().catch(error => {
    console.error('Error:', error);
    process.exit(1);
});