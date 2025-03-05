import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { open } from 'lmdb';

// Types
export enum DeviceCodeStatus {
    PENDING = 'pending',
    AUTHORIZED = 'authorized',
    DENIED = 'denied',
    EXPIRED = 'expired',
    USED = 'used'
}

export interface DeviceCodeData {
    deviceCode: string;
    userCode: string;
    clientId: string;
    scopes: string[];
    userId?: string;
    status: DeviceCodeStatus;
    expiresAt: Date;
    createdAt: Date;
    verificationUri: string;
    verificationUriComplete: string;
    interval: number; // polling interval in seconds
}

// Define the same data directory and file for LMDB as the main storage
const DATA_DIR = path.join(process.cwd(), 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.mdb');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Use the same LMDB environment but with different named databases
const rootDb = open({
    path: DATA_DIR,
    compression: true,
    maxDbs: 10,
    maxReaders: 126,
    overlappingSync: true
});

// Open named databases for device code data
const deviceCodeDb = rootDb.openDB<DeviceCodeData>({
    name: 'deviceCodes',
    encoding: 'json',
    compression: true
});

const userCodeDb = rootDb.openDB<string>({
    name: 'userCodes',
    encoding: 'string'
});

// User code format options
const USER_CODE_LENGTH = 8;
const USER_CODE_CHARS = 'BCDFGHJKLMNPQRSTVWXZ'; // Consonants only for better readability

/**
 * Generate a user-friendly code (like "TGMB-WFPR")
 */
export function generateUserCode(): string {
    let code = '';

    for (let i = 0; i < USER_CODE_LENGTH; i++) {
        // Add a hyphen in the middle
        if (i === USER_CODE_LENGTH / 2) {
            code += '-';
        }
        code += USER_CODE_CHARS.charAt(Math.floor(Math.random() * USER_CODE_CHARS.length));
    }

    return code;
}

/**
 * Create a new device authorization request
 */
export function createDeviceCode(
    clientId: string,
    scopes: string[],
    verificationUri: string,
    expiresIn: number = 900, // 15 minutes
    interval: number = 5 // 5 seconds
): DeviceCodeData {
    // Generate codes
    const deviceCode = crypto.randomBytes(32).toString('hex');
    const userCode = generateUserCode();

    // Create verification URI with code
    const formattedUserCode = userCode.replace(/-/g, '');
    const verificationUriComplete = `${verificationUri}?user_code=${userCode}`;

    // Create device code data
    const deviceCodeData: DeviceCodeData = {
        deviceCode,
        userCode,
        clientId,
        scopes,
        status: DeviceCodeStatus.PENDING,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        createdAt: new Date(),
        verificationUri,
        verificationUriComplete,
        interval
    };

    // Store codes
    deviceCodeDb.putSync(deviceCode, deviceCodeData);

    // Store the user code with and without hyphen for better matching
    userCodeDb.putSync(userCode, deviceCode);
    userCodeDb.putSync(userCode.replace(/-/g, ''), deviceCode);

    return deviceCodeData;
}

/**
 * Find a device code by user code
 */
export function findByUserCode(userCode: string): DeviceCodeData | undefined {
    const deviceCode = userCodeDb.get(userCode);
    if (!deviceCode) return undefined;

    return deviceCodeDb.get(deviceCode);
}

/**
 * Get a device code
 */
export function getDeviceCode(code: string): DeviceCodeData | undefined {
    return deviceCodeDb.get(code);
}

/**
 * Mark a device code as authorized
 */
export function authorizeDeviceCode(userCode: string, userId: string): boolean {
    const deviceCode = userCodeDb.get(userCode);
    if (!deviceCode) return false;

    const data = deviceCodeDb.get(deviceCode);
    if (!data || data.status !== DeviceCodeStatus.PENDING || data.expiresAt < new Date()) {
        return false;
    }

    // Update device code
    const updatedData = {
        ...data,
        status: DeviceCodeStatus.AUTHORIZED,
        userId
    };

    deviceCodeDb.putSync(deviceCode, updatedData);
    return true;
}

/**
 * Mark a device code as denied
 */
export function denyDeviceCode(userCode: string): boolean {
    const deviceCode = userCodeDb.get(userCode);
    if (!deviceCode) return false;

    const data = deviceCodeDb.get(deviceCode);
    if (!data || data.expiresAt < new Date()) {
        return false;
    }

    // Update device code
    const updatedData = {
        ...data,
        status: DeviceCodeStatus.DENIED
    };

    deviceCodeDb.putSync(deviceCode, updatedData);
    return true;
}

/**
 * Mark a device code as used (after token issuance)
 */
export function useDeviceCode(deviceCode: string): boolean {
    const data = deviceCodeDb.get(deviceCode);
    if (!data || data.status !== DeviceCodeStatus.AUTHORIZED || data.expiresAt < new Date()) {
        return false;
    }

    // Update device code
    const updatedData = {
        ...data,
        status: DeviceCodeStatus.USED
    };

    deviceCodeDb.putSync(deviceCode, updatedData);
    return true;
}

/**
 * Clean up expired device codes
 */
export function cleanupExpiredCodesSync(): void {
    const now = new Date();

    try {
        // Check each device code
        for (const { key, value } of deviceCodeDb.getRange()) {
            if (value.expiresAt < now && value.status !== DeviceCodeStatus.EXPIRED) {
                // Mark as expired
                deviceCodeDb.putSync(key, {
                    ...value,
                    status: DeviceCodeStatus.EXPIRED
                });
            }
        }
    } catch (error) {
        console.error('Error cleaning up expired device codes:', error);
    }
}

// Run cleanup every minute
setInterval(cleanupExpiredCodesSync, 60 * 1000);