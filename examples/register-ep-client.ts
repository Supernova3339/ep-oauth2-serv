#!/usr/bin/env ts-node

/**
 * Register Easypanel Example Client
 *
 * This script registers the Easypanel example client with the OAuth2 server.
 * It creates a persistent client with the necessary configuration for the example.
 *
 * Usage:
 *   npm run register-ep-client
 */

import * as storage from '../src/storage/memory';
import { Client } from '../src/types';

async function main() {
    console.log('Registering Easypanel Connect Example Client\n');

    // Initialize storage
    storage.initializeTestClient();

    // Check if client already exists
    const existingClient = storage.getClient('easypanel-example-client');

    if (existingClient) {
        console.log('Easypanel Client already exists:');
        console.log(`- Client ID: ${existingClient.id}`);
        console.log(`- Client Secret: ${existingClient.secret}`);
        console.log(`- Redirect URIs: ${existingClient.redirectUris.join(', ')}`);
        console.log(`- Scopes: ${existingClient.allowedScopes.join(', ')}`);
        return;
    }

    // Create the OpenID Connect example client
    const client = storage.createClient(
        'OpenID Connect Example Client',
        ['http://localhost:8080/callback'],
        ['openid', 'profile', 'email'],
        true // Make it persistent
    );

    // Update the client with known values
    const updatedClient = storage.updateClient(client.id, {
        name: 'OpenID Connect Example Client',
        redirectUris: ['http://localhost:8080/callback'],
        allowedScopes: ['openid', 'profile', 'email'],
        secret: 'openid-example-secret'
    });

    // Delete the original client
    storage.deleteClient(client.id);

    // Create a new client with the specific ID we want
    const finalClient = storage.createClient(
        'OpenID Connect Example Client',
        ['http://localhost:8080/callback'],
        ['openid', 'profile', 'email'],
        true
    );

    // Update the newly created client with our preferred values
    const configuredClient = storage.updateClient(finalClient.id, {
        id: 'openid-example-client',
        secret: 'openid-example-secret'
    });

    console.log('Registered OpenID Connect Example Client:');
    if (configuredClient) {
        console.log(`- Client ID: ${configuredClient.id}`);
        console.log(`- Client Secret: ${configuredClient.secret}`);
        console.log(`- Redirect URIs: ${configuredClient.redirectUris.join(', ')}`);
        console.log(`- Scopes: ${configuredClient.allowedScopes.join(', ')}`);
    } else {
        console.log(`- Client ID: openid-example-client (manually set)`);
        console.log(`- Client Secret: openid-example-secret (manually set)`);
        console.log(`- Redirect URIs: ${finalClient.redirectUris.join(', ')}`);
        console.log(`- Scopes: ${finalClient.allowedScopes.join(', ')}`);
    }

    console.log('\nYou can now run the OpenID Connect example.');
}

// Run the main function
main().catch(error => {
    console.error('Error:', error);
    process.exit(1);
});