// src/storage/db-helpers.ts
// Helper functions to retrieve all data from LMDB databases for admin views

import path from 'path';
import { open } from 'lmdb';
import { AuthorizationCode, Token } from '../types';
import { DeviceCodeData } from './device-lmdb';

// Define the data directory
const DATA_DIR = path.join(process.cwd(), 'data');

// Open the LMDB environment
const rootDb = open({
    path: DATA_DIR,
    compression: true,
    maxDbs: 10,
    maxReaders: 126,
    overlappingSync: true
});

// Open database references
const dbRefs = {
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
    }),
    deviceCodes: rootDb.openDB<DeviceCodeData>({
        name: 'deviceCodes',
        encoding: 'json',
        compression: true
    })
};

/**
 * Gets all authorization codes from the database
 */
export async function getAllAuthorizationCodes(): Promise<AuthorizationCode[]> {
    const codes: AuthorizationCode[] = [];
    for (const { value } of dbRefs.authorizationCodes.getRange()) {
        codes.push(value);
    }
    return codes;
}

/**
 * Gets all access tokens from the database
 */
export async function getAllTokens(): Promise<Token[]> {
    const tokens: Token[] = [];
    for (const { value } of dbRefs.tokens.getRange()) {
        tokens.push(value);
    }
    return tokens;
}

/**
 * Gets all refresh tokens from the database
 */
export async function getAllRefreshTokens(): Promise<{refreshToken: string, accessToken: string}[]> {
    const refreshTokens: {refreshToken: string, accessToken: string}[] = [];
    for (const { key, value } of dbRefs.refreshTokens.getRange()) {
        refreshTokens.push({
            refreshToken: key as string,
            accessToken: value as string
        });
    }
    return refreshTokens;
}

/**
 * Gets all device codes from the database
 */
export async function getAllDeviceCodes(): Promise<DeviceCodeData[]> {
    const codes: DeviceCodeData[] = [];
    for (const { value } of dbRefs.deviceCodes.getRange()) {
        codes.push(value);
    }
    return codes;
}