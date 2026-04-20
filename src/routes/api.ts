import crypto from 'crypto';
import { Router, Request, Response } from 'express';
import { requireAuthOrApiKey, requireAdminOrApiKey } from '../middleware';
import * as storage from '../storage/lmdb';
import { epTrpc, epTrpcPost } from '../easypanel';

const router = Router();

router.get('/api/branding', async (_req: Request, res: Response) => {
    const [iface, links] = await Promise.all([
        epTrpc<{ darkLogo?: string | null; lightLogo?: string | null; logomark?: string | null }>('branding.getInterfaceSettingsPublic'),
        epTrpc<{ hideOtherLinks?: boolean }>('branding.getLinksSettings'),
    ]);
    return res.json({
        darkLogo: iface?.darkLogo ?? null,
        lightLogo: iface?.lightLogo ?? null,
        logomark: iface?.logomark ?? null,
        hideOtherLinks: links?.hideOtherLinks ?? false,
    });
});

router.get('/api/clients', requireAuthOrApiKey, requireAdminOrApiKey, (req: Request, res: Response) => {
    const clients = storage.listClients().map(client => ({
        id: client.id,
        name: client.name,
        redirectUris: client.redirectUris,
        allowedScopes: client.allowedScopes,
        createdAt: client.createdAt,
        persistent: client.persistent || false
    }));
    return res.json({ success: true, clients });
});

router.get('/api/clients/:id', requireAuthOrApiKey, requireAdminOrApiKey, (req: Request, res: Response) => {
    const client = storage.getClient(req.params.id);
    if (!client) {
        return res.status(404).json({ success: false, error: 'Client not found' });
    }
    return res.json({
        success: true,
        client: {
            id: client.id,
            name: client.name,
            redirectUris: client.redirectUris,
            allowedScopes: client.allowedScopes,
            createdAt: client.createdAt,
            persistent: client.persistent || false
        }
    });
});

router.post('/api/clients', requireAuthOrApiKey, requireAdminOrApiKey, (req: Request, res: Response) => {
    const { name, redirectUris, allowedScopes, persistent } = req.body as {
        name: string;
        redirectUris: string[];
        allowedScopes: string[];
        persistent?: boolean;
    };

    if (!name || !Array.isArray(redirectUris) || !Array.isArray(allowedScopes)) {
        return res.status(400).json({ success: false, error: 'Missing or invalid required fields' });
    }

    const client = storage.createClient(name, redirectUris, allowedScopes, !!persistent);
    return res.status(201).json({
        success: true,
        client: {
            id: client.id,
            name: client.name,
            secret: client.secret,
            redirectUris: client.redirectUris,
            allowedScopes: client.allowedScopes,
            createdAt: client.createdAt,
            persistent: client.persistent || false
        }
    });
});

router.delete('/api/clients/:id', requireAuthOrApiKey, requireAdminOrApiKey, (req: Request, res: Response) => {
    const client = storage.getClient(req.params.id);
    if (!client) {
        return res.status(404).json({ success: false, error: 'Client not found' });
    }

    if (!storage.deleteClient(req.params.id)) {
        return res.status(500).json({ success: false, error: 'Failed to delete client' });
    }

    return res.json({ success: true, message: 'Client deleted successfully' });
});

router.put('/api/clients/:id', requireAuthOrApiKey, requireAdminOrApiKey, (req: Request, res: Response) => {
    const client = storage.getClient(req.params.id);
    if (!client) {
        return res.status(404).json({ success: false, error: 'Client not found' });
    }

    const { name, redirectUris, allowedScopes, persistent } = req.body as {
        name?: string;
        redirectUris?: string[];
        allowedScopes?: string[];
        persistent?: boolean;
    };

    const updatedClient = storage.updateClient(client.id, {
        name,
        redirectUris,
        allowedScopes,
        persistent: persistent !== undefined ? persistent : client.persistent
    });

    if (!updatedClient) {
        return res.status(500).json({ success: false, error: 'Failed to update client' });
    }

    return res.json({
        success: true,
        client: {
            id: updatedClient.id,
            name: updatedClient.name,
            redirectUris: updatedClient.redirectUris,
            allowedScopes: updatedClient.allowedScopes,
            createdAt: updatedClient.createdAt,
            persistent: updatedClient.persistent || false
        }
    });
});

router.post('/api/clients/:id/secret', requireAuthOrApiKey, requireAdminOrApiKey, (req: Request, res: Response) => {
    const client = storage.getClient(req.params.id);
    if (!client) {
        return res.status(404).json({ success: false, error: 'Client not found' });
    }
    const newSecret = crypto.randomBytes(32).toString('hex');
    const updated = storage.updateClient(req.params.id, { secret: newSecret });
    if (!updated) {
        return res.status(500).json({ success: false, error: 'Failed to regenerate secret' });
    }
    return res.json({ success: true, clientId: updated.id, clientName: updated.name, clientSecret: newSecret });
});

// ── Users (admin) ──────────────────────────────────────────────────────────

router.get('/api/users', requireAuthOrApiKey, requireAdminOrApiKey, async (_req: Request, res: Response) => {
    const data = await epTrpc<{ users: unknown[] }>('users.listUsers');
    return res.json({ success: true, users: data?.users ?? [] });
});

router.post('/api/users', requireAuthOrApiKey, requireAdminOrApiKey, async (req: Request, res: Response) => {
    const { email, password, admin } = req.body as { email: string; password: string; admin: boolean };
    const result = await epTrpcPost('users.createUser', { email, password, admin });
    if (!result) return res.status(500).json({ success: false, error: 'Failed to create user' });
    return res.json({ success: true });
});

router.put('/api/users/:id', requireAuthOrApiKey, requireAdminOrApiKey, async (req: Request, res: Response) => {
    const { password, admin } = req.body as { password?: string; admin: boolean };
    const result = await epTrpcPost('users.updateUser', { id: req.params.id, ...(password ? { password } : {}), admin });
    if (!result) return res.status(500).json({ success: false, error: 'Failed to update user' });
    return res.json({ success: true });
});

router.delete('/api/users/:id', requireAuthOrApiKey, requireAdminOrApiKey, async (req: Request, res: Response) => {
    const result = await epTrpcPost('users.destroyUser', { id: req.params.id });
    if (!result) return res.status(500).json({ success: false, error: 'Failed to delete user' });
    return res.json({ success: true });
});

router.post('/api/users/:id/generate-api-token', requireAuthOrApiKey, requireAdminOrApiKey, async (req: Request, res: Response) => {
    const result = await epTrpcPost<{ apiToken: string }>('users.generateApiToken', { id: req.params.id });
    if (!result) return res.status(500).json({ success: false, error: 'Failed to generate API token' });
    return res.json({ success: true, apiToken: (result as { apiToken?: string }).apiToken });
});

router.post('/api/users/:id/revoke-api-token', requireAuthOrApiKey, requireAdminOrApiKey, async (req: Request, res: Response) => {
    const result = await epTrpcPost('users.revokeApiToken', { id: req.params.id });
    if (!result) return res.status(500).json({ success: false, error: 'Failed to revoke API token' });
    return res.json({ success: true });
});

// ── Settings (current user) ────────────────────────────────────────────────

router.post('/api/settings/change-credentials', requireAuthOrApiKey, async (req: Request, res: Response) => {
    const { email, oldPassword, newPassword } = req.body as { email: string; oldPassword: string; newPassword: string };
    const result = await epTrpcPost('settings.changeCredentials', { email, oldPassword, newPassword });
    if (!result) return res.status(400).json({ success: false, error: 'Failed to change credentials. Check your current password.' });
    return res.json({ success: true });
});

// ── 2FA (current user) ─────────────────────────────────────────────────────

router.post('/api/2fa/configure', requireAuthOrApiKey, async (_req: Request, res: Response) => {
    const result = await epTrpcPost<{ secret: string; otpAuthUrl: string }>('twoFactor.configure', {});
    if (!result) return res.status(500).json({ success: false, error: 'Failed to configure 2FA' });
    return res.json({ success: true, ...result });
});

router.post('/api/2fa/enable', requireAuthOrApiKey, async (req: Request, res: Response) => {
    const { code } = req.body as { code: string };
    const result = await epTrpcPost('twoFactor.enable', { code });
    if (!result) return res.status(500).json({ success: false, error: 'Invalid code' });
    return res.json({ success: true });
});

router.post('/api/2fa/disable', requireAuthOrApiKey, async (_req: Request, res: Response) => {
    const result = await epTrpcPost('twoFactor.disable', {});
    if (!result) return res.status(500).json({ success: false, error: 'Failed to disable 2FA' });
    return res.json({ success: true });
});

export default router;
