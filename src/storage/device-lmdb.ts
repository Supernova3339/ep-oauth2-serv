import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { open } from 'lmdb';

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
    interval: number;
}

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

const deviceCodeDb = rootDb.openDB<DeviceCodeData>({ name: 'deviceCodes', encoding: 'json', compression: true });
const userCodeDb = rootDb.openDB<string>({ name: 'userCodes', encoding: 'string' });

const USER_CODE_LENGTH = 8;
const USER_CODE_CHARS = 'BCDFGHJKLMNPQRSTVWXZ';

function generateUserCode(): string {
    const bytes = crypto.randomBytes(USER_CODE_LENGTH);
    let code = '';
    for (let i = 0; i < USER_CODE_LENGTH; i++) {
        if (i === USER_CODE_LENGTH / 2) code += '-';
        code += USER_CODE_CHARS[bytes[i] % USER_CODE_CHARS.length];
    }
    return code;
}

export function createDeviceCode(
    clientId: string,
    scopes: string[],
    verificationUri: string,
    expiresIn = 900,
    interval = 5
): DeviceCodeData {
    const deviceCode = crypto.randomBytes(32).toString('hex');
    const userCode = generateUserCode();

    const deviceCodeData: DeviceCodeData = {
        deviceCode,
        userCode,
        clientId,
        scopes,
        status: DeviceCodeStatus.PENDING,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        createdAt: new Date(),
        verificationUri,
        verificationUriComplete: `${verificationUri}?user_code=${userCode}`,
        interval
    };

    deviceCodeDb.putSync(deviceCode, deviceCodeData);
    userCodeDb.putSync(userCode, deviceCode);
    userCodeDb.putSync(userCode.replace(/-/g, ''), deviceCode);

    return deviceCodeData;
}

export function findByUserCode(userCode: string): DeviceCodeData | undefined {
    const deviceCode = userCodeDb.get(userCode);
    if (!deviceCode) return undefined;
    return deviceCodeDb.get(deviceCode);
}

export function getDeviceCode(code: string): DeviceCodeData | undefined {
    return deviceCodeDb.get(code);
}

export function authorizeDeviceCode(userCode: string, userId: string): boolean {
    const deviceCode = userCodeDb.get(userCode);
    if (!deviceCode) return false;

    const data = deviceCodeDb.get(deviceCode);
    if (!data || data.status !== DeviceCodeStatus.PENDING || data.expiresAt < new Date()) return false;

    deviceCodeDb.putSync(deviceCode, { ...data, status: DeviceCodeStatus.AUTHORIZED, userId });
    return true;
}

export function denyDeviceCode(userCode: string): boolean {
    const deviceCode = userCodeDb.get(userCode);
    if (!deviceCode) return false;

    const data = deviceCodeDb.get(deviceCode);
    if (!data || data.expiresAt < new Date()) return false;

    deviceCodeDb.putSync(deviceCode, { ...data, status: DeviceCodeStatus.DENIED });
    return true;
}

export function useDeviceCode(deviceCode: string): boolean {
    const data = deviceCodeDb.get(deviceCode);
    if (!data || data.status !== DeviceCodeStatus.AUTHORIZED || data.expiresAt < new Date()) return false;

    deviceCodeDb.putSync(deviceCode, { ...data, status: DeviceCodeStatus.USED });
    return true;
}

export function cleanupExpiredCodesSync(): void {
    const now = new Date();
    try {
        for (const { key, value } of deviceCodeDb.getRange()) {
            if (value.expiresAt < now && value.status !== DeviceCodeStatus.EXPIRED) {
                deviceCodeDb.putSync(key, { ...value, status: DeviceCodeStatus.EXPIRED });
            }
        }
    } catch (error) {
        console.error('Error cleaning up expired device codes:', error);
    }
}

setInterval(cleanupExpiredCodesSync, 60 * 1000);
