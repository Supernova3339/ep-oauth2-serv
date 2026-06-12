#!/usr/bin/env ts-node

import axios from 'axios';
import open from 'open';
import fs from 'fs';
import path from 'path';

const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:3000';

function loadConfig() {
    try {
        const raw = fs.readFileSync(path.join(__dirname, 'config.json'), 'utf-8');
        return JSON.parse(raw).device as { id: string; secret: string };
    } catch {
        return { id: 'test-client', secret: 'test-secret' };
    }
}

const { id: CLIENT_ID, secret: CLIENT_SECRET } = loadConfig();

interface DeviceAuthResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
}

interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    id_token?: string;
    scope: string;
}

interface UserInfo {
    sub: string;
    email?: string;
    name?: string;
}

async function requestDeviceCode(): Promise<DeviceAuthResponse> {
    const body = new URLSearchParams({ client_id: CLIENT_ID, scope: 'profile email' });
    const { data } = await axios.post<DeviceAuthResponse>(`${SERVER_URL}/oauth/device`, body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return data;
}

async function pollForToken(deviceCode: string, interval: number): Promise<TokenResponse> {
    let pollMs = (interval || 5) * 1000;
    const body = new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
    });

    while (true) {
        try {
            const { data } = await axios.post<TokenResponse>(`${SERVER_URL}/oauth/token`, body.toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
            return data;
        } catch (err) {
            if (axios.isAxiosError(err) && err.response?.data) {
                const { error } = err.response.data as { error: string };
                if (error === 'authorization_pending') process.stdout.write('.');
                else if (error === 'slow_down') pollMs += 5000;
                else if (error === 'expired_token') throw new Error('Device code expired.');
                else if (error === 'access_denied') throw new Error('User denied authorization.');
                else throw err;
            } else {
                throw err;
            }
        }
        await new Promise(r => setTimeout(r, pollMs));
    }
}

async function getUserInfo(accessToken: string): Promise<UserInfo> {
    const { data } = await axios.get<UserInfo>(`${SERVER_URL}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}` }
    });
    return data;
}

async function main() {
    console.log(`Device Authorization Flow  [${CLIENT_ID}]\n`);

    const deviceAuth = await requestDeviceCode();
    console.log(`User code:        ${deviceAuth.user_code}`);
    console.log(`Verification URL: ${deviceAuth.verification_uri}`);
    console.log('\nOpening browser...');
    await open(deviceAuth.verification_uri_complete);

    console.log('\nPolling for authorization');
    const token = await pollForToken(deviceAuth.device_code, deviceAuth.interval);

    console.log('\nAuthorized.');
    console.log(`Access token:  ${token.access_token.slice(0, 12)}...`);
    console.log(`Expires in:    ${token.expires_in}s`);
    console.log(`Scopes:        ${token.scope}`);

    const userInfo = await getUserInfo(token.access_token);
    console.log('\nUser info:', userInfo);
}

main().catch(err => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
});
