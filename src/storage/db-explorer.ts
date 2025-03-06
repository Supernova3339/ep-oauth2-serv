// src/storage/db-explorer.ts
// A more robust generic LMDB database explorer that handles errors gracefully

import path from 'path';
import fs from 'fs';
import { open, RootDatabase } from 'lmdb';

// Define the data directory - assuming it's in the project root
const DATA_DIR = path.join(process.cwd(), 'data');

// Type definitions for clarity
interface PropertyInfo {
    type: string;
    sample?: any;
}

interface StructureInfo {
    type: string;
    value?: any;
    length?: number;
    sampleElement?: any;
    properties?: Record<string, PropertyInfo>;
}

interface DbEntry {
    key: any;
    value: any;
}

/**
 * Opens the LMDB environment
 */
function openLmdbEnvironment(): RootDatabase {
    // Ensure the data directory exists
    if (!fs.existsSync(DATA_DIR)) {
        throw new Error(`Data directory not found: ${DATA_DIR}`);
    }

    // Open the root database with maximum configuration
    return open({
        path: DATA_DIR,
        compression: true,
        maxDbs: 100,
        maxReaders: 126,
        overlappingSync: true
    });
}

/**
 * Gets a list of all databases in the environment
 * This uses a more direct approach by looking at the actual files
 */
async function listAllDatabases(): Promise<string[]> {
    const rootDb = openLmdbEnvironment();

    try {
        // Try to get the list of databases from the environment
        const dbNames = [];

        // These are likely LMDB databases in the environment
        const dbFiles = fs.readdirSync(DATA_DIR)
            .filter(file => !file.startsWith('.') && !file.endsWith('.mdb-lock'));

        // Return the list of database names (removing .mdb extension if present)
        for (const file of dbFiles) {
            if (file.endsWith('.mdb')) {
                dbNames.push(file.slice(0, -4));
            } else {
                dbNames.push(file);
            }
        }

        return dbNames;
    } catch (error) {
        console.error('Error listing databases:', error);
        return [];
    }
}

/**
 * Test if a database can be opened and read
 */
async function testDatabase(rootDb: RootDatabase, dbName: string): Promise<boolean> {
    try {
        // Try to open the database
        const db = rootDb.openDB({ name: dbName });

        // Try to read something from it - just checking if we can iterate
        const iterator = db.getRange({ limit: 1 });
        // Just check if we can get an iterator - no need to actually iterate
        return !!iterator;
    } catch (error) {
        console.log(`Database ${dbName} exists but cannot be read:`, error);
        return false;
    }
}

/**
 * Safely retrieve all entries from a database, handling errors gracefully
 */
async function safelyRetrieveEntries(rootDb: RootDatabase, dbName: string): Promise<DbEntry[]> {
    const entries: DbEntry[] = [];

    try {
        // Try to open the database with different encoding options
        const db = rootDb.openDB({
            name: dbName,
            // Don't specify encoding to get raw buffer data
        });

        // Use for...of loop with the iterable instead of manual next() calls
        for await (const entry of db.getRange()) {
            try {
                // Try to interpret the value as different formats
                let value = entry.value;

                // If it's a buffer, try to convert to string or JSON
                if (Buffer.isBuffer(value)) {
                    try {
                        // Try to interpret as UTF-8 string
                        const strValue = value.toString('utf-8');

                        // See if it's valid JSON
                        try {
                            value = JSON.parse(strValue);
                        } catch {
                            // Not JSON, use the string
                            value = strValue;
                        }
                    } catch {
                        // If string conversion fails, leave as buffer but convert to hex
                        value = `<Buffer: ${value.toString('hex').substring(0, 32)}${value.length > 32 ? '...' : ''}>`;
                    }
                }

                entries.push({
                    key: entry.key,
                    value: value
                });
            } catch (entryError) {
                // Handle errors for individual entries
                console.error(`Error processing entry in ${dbName}:`, entryError);
                entries.push({
                    key: entry.key,
                    value: `<Error: Could not read value>`
                });
            }
        }
    } catch (error) {
        console.error(`Error opening database ${dbName}:`, error);
    }

    return entries;
}

/**
 * Analyze a database entry to infer its type and structure
 */
function analyzeEntryStructure(entry: any): StructureInfo {
    // Handle errors or unreadable data
    if (typeof entry === 'string' && entry.startsWith('<Error:')) {
        return {
            type: 'error',
            value: entry
        };
    }

    // Handle buffer data
    if (typeof entry === 'string' && entry.startsWith('<Buffer:')) {
        return {
            type: 'buffer',
            value: entry
        };
    }

    // If it's a primitive type, return it as is
    if (typeof entry !== 'object' || entry === null) {
        return {
            type: typeof entry,
            value: entry
        };
    }

    // If it's an array, analyze its elements
    if (Array.isArray(entry)) {
        return {
            type: 'array',
            length: entry.length,
            sampleElement: entry.length > 0 ? analyzeEntryStructure(entry[0]) : null
        };
    }

    // It's an object - extract its properties
    const properties: Record<string, PropertyInfo> = {};

    for (const [key, value] of Object.entries(entry)) {
        // For Date objects, convert to ISO string for readability
        if (value instanceof Date) {
            properties[key] = {
                type: 'Date',
                sample: value.toISOString()
            };
        }
        // For simple values, just store the type
        else if (typeof value !== 'object' || value === null) {
            properties[key] = {
                type: typeof value,
                sample: value
            };
        }
        // For nested objects, just note it's an object
        else if (typeof value === 'object') {
            properties[key] = {
                type: Array.isArray(value) ? 'array' : 'object',
                sample: JSON.stringify(value).substring(0, 50) + (JSON.stringify(value).length > 50 ? '...' : '')
            };
        }
    }

    return {
        type: 'object',
        properties
    };
}

/**
 * Get all database information without predefined knowledge
 */
export async function exploreAllDatabases() {
    const rootDb = openLmdbEnvironment();
    const databaseNames = await listAllDatabases();

    const result: Record<string, any> = {};

    // Get entries from each database and analyze them
    for (const dbName of databaseNames) {
        try {
            // Skip lock files and other non-database files
            if (dbName.endsWith('-lock') || dbName.startsWith('lock.') || dbName === 'data.mdb' || dbName === 'lock.mdb') {
                continue;
            }

            // Skip if can't open the database
            if (!(await testDatabase(rootDb, dbName))) {
                continue;
            }

            // Get entries from the database
            const entries = await safelyRetrieveEntries(rootDb, dbName);

            // Skip empty databases
            if (entries.length === 0) continue;

            // Analyze the structure of the first entry to get an idea of the schema
            const sampleStructure = entries.length > 0
                ? analyzeEntryStructure(entries[0].value)
                : null;

            result[dbName] = {
                entries,
                count: entries.length,
                inferred_structure: sampleStructure
            };
        } catch (error) {
            console.error(`Error exploring database ${dbName}:`, error);
            // Still include the database in the results, but with an error
            result[dbName] = {
                entries: [],
                count: 0,
                error: `Error: ${error instanceof Error ? error.message : String(error)}`
            };
        }
    }

    return result;
}

/**
 * Extract information about a specific database
 */
export async function exploreDatabaseByName(dbName: string) {
    const rootDb = openLmdbEnvironment();

    try {
        // Test if database can be opened
        if (!(await testDatabase(rootDb, dbName))) {
            return {
                name: dbName,
                entries: [],
                count: 0,
                error: 'Cannot read database'
            };
        }

        // Get entries safely
        const entries = await safelyRetrieveEntries(rootDb, dbName);

        // Analyze the structure if we have entries
        const sampleStructure = entries.length > 0
            ? analyzeEntryStructure(entries[0].value)
            : null;

        return {
            name: dbName,
            entries,
            count: entries.length,
            inferred_structure: sampleStructure
        };
    } catch (error) {
        console.error(`Error exploring database ${dbName}:`, error);
        return {
            name: dbName,
            entries: [],
            count: 0,
            error: `Error: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}

/**
 * Get the raw entry from any database by key
 */
export async function getEntryByKey(dbName: string, key: string) {
    const rootDb = openLmdbEnvironment();

    try {
        // Open without specifying encoding
        const db = rootDb.openDB({ name: dbName });

        // Try to get the entry
        const value = await db.get(key);

        // Handle different data types
        if (Buffer.isBuffer(value)) {
            try {
                // Try to interpret as UTF-8 string
                const strValue = value.toString('utf-8');

                // See if it's valid JSON
                try {
                    return JSON.parse(strValue);
                } catch {
                    // Not JSON, use the string
                    return strValue;
                }
            } catch {
                // If string conversion fails, return info about the buffer
                return `<Buffer: ${value.toString('hex').substring(0, 100)}${value.length > 100 ? '...' : ''}>`;
            }
        }

        // Return the value as is
        return value;
    } catch (error) {
        console.error(`Error getting entry from ${dbName} with key ${key}:`, error);
        return `Error: ${error instanceof Error ? error.message : String(error)}`;
    }
}

/**
 * Guesses the schema of a database by sampling multiple entries
 */
export async function guessDbSchema(dbName: string, sampleSize = 10) {
    const rootDb = openLmdbEnvironment();

    try {
        // Test if database can be opened
        if (!(await testDatabase(rootDb, dbName))) {
            return {
                name: dbName,
                count: 0,
                sampleSize: 0,
                inferredSchema: {},
                isConsistent: false,
                error: 'Cannot read database'
            };
        }

        // Get entries safely
        const entries = await safelyRetrieveEntries(rootDb, dbName);

        // Take a sample of entries to analyze
        const samplesToAnalyze = entries.slice(0, Math.min(sampleSize, entries.length));

        // Analyze each sample
        const schemas = samplesToAnalyze.map(entry => analyzeEntryStructure(entry.value));

        // Combine schemas to find common properties
        const commonProperties: Record<string, Set<string>> = {};

        // Start with the first schema's properties as the base
        if (schemas.length > 0 && schemas[0].type === 'object' && schemas[0].properties) {
            for (const [prop, details] of Object.entries(schemas[0].properties)) {
                commonProperties[prop] = new Set([details.type]);
            }

            // Check which properties exist in all schemas and what types they have
            for (let i = 1; i < schemas.length; i++) {
                const schema = schemas[i];
                if (schema.type !== 'object' || !schema.properties) continue;

                // Check existing properties
                for (const prop in commonProperties) {
                    if (schema.properties[prop]) {
                        commonProperties[prop].add(schema.properties[prop].type);
                    } else {
                        // Property doesn't exist in this sample, mark as optional
                        commonProperties[prop].add('undefined');
                    }
                }

                // Add new properties found in this schema
                for (const prop in schema.properties) {
                    if (!commonProperties[prop]) {
                        commonProperties[prop] = new Set([schema.properties[prop].type]);
                        // Mark as optional since it wasn't in previous schemas
                        commonProperties[prop].add('undefined');
                    }
                }
            }
        }

        // Convert sets to arrays for easier JSON serialization
        const inferredSchema: Record<string, string[]> = {};
        for (const [prop, types] of Object.entries(commonProperties)) {
            inferredSchema[prop] = Array.from(types);
        }

        return {
            name: dbName,
            count: entries.length,
            sampleSize: samplesToAnalyze.length,
            inferredSchema,
            isConsistent: Object.values(inferredSchema).every(types => types.length === 1)
        };
    } catch (error) {
        console.error(`Error guessing schema for ${dbName}:`, error);
        return {
            name: dbName,
            count: 0,
            sampleSize: 0,
            inferredSchema: {},
            isConsistent: false,
            error: `Error: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}