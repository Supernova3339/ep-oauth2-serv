#!/usr/bin/env ts-node

/**
 * Migration script to convert in-memory storage to LMDB
 *
 * This script reads the existing clients.json file and populates the LMDB database.
 *
 * Usage:
 *   npx ts-node scripts/migrate-to-lmdb.ts
 */

import fs from 'fs';
import path from 'path';
import { Client } from '../src/types';
import { open } from 'lmdb';

// File paths
const OLD_DATA_DIR = path.join(process.cwd(), 'data');
const CLIENTS_FILE = path.join(OLD_DATA_DIR, 'clients.json');
const NEW_DATA_DIR = path.join(process.cwd(), 'data');

// Initialize LMDB environment
const rootDb = open({
    path: NEW_DATA_DIR,
    compression: true,
    maxDbs: 10,
    maxReaders: 126,
    overlappingSync: true
});

// Open the clients database
const clientsDb = rootDb.openDB({
    name: 'clients',
    encoding: 'json',
    compression: true
});

function migrateClientsToLmdb() {
    console.log('Starting migration from JSON to LMDB...');

    // Create the data directory if it doesn't exist
    if (!fs.existsSync(NEW_DATA_DIR)) {
        fs.mkdirSync(NEW_DATA_DIR, { recursive: true });
        console.log(`Created LMDB data directory at ${NEW_DATA_DIR}`);
    }

    // Check if old clients file exists
    if (!fs.existsSync(CLIENTS_FILE)) {
        console.log(`No clients file found at ${CLIENTS_FILE}. Nothing to migrate.`);
        return;
    }

    try {
        // Read the old clients file
        const data = fs.readFileSync(CLIENTS_FILE, 'utf8');
        const clients = JSON.parse(data) as Client[];

        console.log(`Found ${clients.length} clients to migrate.`);

        // Add each client to LMDB
        for (const client of clients) {
            // Convert string dates back to Date objects
            client.createdAt = new Date(client.createdAt);

            // Store in LMDB using synchronous operation
            clientsDb.putSync(client.id, client);
            console.log(`Migrated client: ${client.id} (${client.name})`);
        }

        console.log('Migration complete!');
        console.log(`${clients.length} clients have been migrated to LMDB.`);

        // Create a backup of the old clients file
        const backupPath = CLIENTS_FILE + '.bak';
        fs.copyFileSync(CLIENTS_FILE, backupPath);
        console.log(`A backup of your clients.json file has been created at ${backupPath}`);

    } catch (error) {
        console.error('Error during migration:', error);
        process.exit(1);
    }
}

// Run the migration
try {
    migrateClientsToLmdb();
} catch (error) {
    console.error('Unhandled error during migration:', error);
    process.exit(1);
}