#!/usr/bin/env ts-node

import 'dotenv/config';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:3000';
const API_KEY = process.env.CLIENT_API_KEY;

if (!API_KEY) {
    console.error('Set CLIENT_API_KEY to your server\'s API key and re-run.');
    process.exit(1);
}

interface CreatedClient {
    id: string;
    name: string;
    secret: string;
}

async function createClient(
    name: string,
    redirectUris: string[],
    allowedScopes: string[]
): Promise<CreatedClient> {
    const { data } = await axios.post(
        `${SERVER_URL}/api/clients`,
        { name, redirectUris, allowedScopes, persistent: true },
        { headers: { 'X-API-Key': API_KEY } }
    );
    return data.client as CreatedClient;
}

async function main() {
    console.log(`Creating example clients on ${SERVER_URL}\n`);

    const device = await createClient(
        'Device Flow Example',
        ['http://localhost:8080/callback'],
        ['profile', 'email']
    );
    console.log(`Device client\n  ID:     ${device.id}\n  Secret: ${device.secret}`);

    const openid = await createClient(
        'OpenID Connect Example',
        ['http://localhost:8080/callback'],
        ['openid', 'profile', 'email']
    );
    console.log(`\nOpenID client\n  ID:     ${openid.id}\n  Secret: ${openid.secret}`);

    const config = { device, openid };
    fs.writeFileSync(path.join(__dirname, 'config.json'), JSON.stringify(config, null, 2));
    console.log('\nSaved to config.json — run npm run device or npm run openid');
}

main().catch(err => {
    const msg = axios.isAxiosError(err)
        ? `${err.response?.status} ${JSON.stringify(err.response?.data)}`
        : err instanceof Error ? err.message : err;
    console.error(msg);
    process.exit(1);
});
