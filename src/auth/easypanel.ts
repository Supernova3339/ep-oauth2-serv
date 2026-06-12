import axios from 'axios';
import https from 'https';
import { EASYPANEL_URL, NODE_ENV } from '../config';
import { EasypanelUser, LoginResponse } from '../types';
import { epTrpc, epTrpcWithToken } from '../easypanel';

const client = axios.create({
    httpsAgent: NODE_ENV !== 'production'
        ? new https.Agent({ rejectUnauthorized: false })
        : undefined
});

export async function validateEasypanelCredentials(
    email: string,
    password: string,
    code?: string
): Promise<LoginResponse> {
    try {
        const payload: Record<string, unknown> = { json: { email, password } };
        if (code) (payload.json as Record<string, unknown>).code = code;

        const response = await client.post(
            `${EASYPANEL_URL}/api/rpc/auth/login`,
            payload,
            { headers: { 'Content-Type': 'application/json' } }
        );

        const data = response.data?.json;
        // console.log('[easypanel] auth/login response:', JSON.stringify(response.data, (key, value) => key === 'token' ? '[redacted]' : value));

        if (data?.twoFactorEnabled === true) {
            return { success: false, twoFactorRequired: true };
        }

        if (data?.token) {
            const user = await getUserInfo(data.token);
            if (user) return { success: true, user, token: data.token };
            return { success: false, error: 'Unable to fetch user information' };
        }

        return { success: false, error: 'Invalid credentials' };
    } catch (error) {
        if (axios.isAxiosError(error) && error.response) {
            const responseData = error.response.data;
            console.log('[easypanel] auth/login error response:', error.response.status, JSON.stringify(responseData));
            let errorMessage = responseData?.json?.message
                || responseData?.error?.json?.message
                || responseData?.error?.message
                || responseData?.message
                || (typeof responseData === 'string' ? responseData : 'Authentication failed');

            if (responseData?.json?.code === 'TOO_MANY_REQUESTS') {
                const resetMs = responseData.json.data?.reset;
                const waitSeconds = resetMs ? Math.max(0, Math.ceil((resetMs - Date.now()) / 1000)) : null;
                errorMessage = waitSeconds
                    ? `Too many login attempts. Please try again in ${waitSeconds} seconds.`
                    : 'Too many login attempts. Please try again later.';
            } else if (errorMessage.includes('Invalid Code')) {
                errorMessage = 'Invalid verification code. Please try again.';
            } else if (errorMessage.includes('expired')) {
                errorMessage = 'Verification code has expired. Please request a new one.';
            }

            return { success: false, error: errorMessage };
        }

        console.error('Error validating Easypanel credentials:', error);
        return { success: false, error: 'Authentication service unavailable' };
    }
}

export async function getUserInfo(token: string): Promise<EasypanelUser | null> {
    try {
        const userData = await epTrpcWithToken<{ id: string; email: string; admin: boolean; twoFactorEnabled: boolean }>('auth.getUser', token);
        if (!userData?.id) return null;
        return {
            id: userData.id,
            email: userData.email,
            admin: userData.admin ?? false,
            twoFactorEnabled: userData.twoFactorEnabled ?? false,
        };
    } catch (error) {
        console.error('Error fetching user info:', error);
        return null;
    }
}

export async function listUsers(token: string): Promise<EasypanelUser[] | null> {
    try {
        const response = await client.get(`${EASYPANEL_URL}/api/rpc/users/listUsers`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        return response.data?.json?.users ?? null;
    } catch (error) {
        console.error('Error listing users:', error);
        return null;
    }
}

export async function getUserById(token: string, userId: string): Promise<EasypanelUser | null> {
    const users = await listUsers(token);
    if (!users) return null;
    return users.find(u => u.id === userId) ?? null;
}
