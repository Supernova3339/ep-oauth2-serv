import { Router, Request, Response } from 'express';
import { requireAuth, requireAdmin } from '../middleware';
import * as storage from '../storage/memory';

const router = Router();

// List all OAuth clients
router.get('/api/clients', requireAuth, requireAdmin, (req: Request, res: Response) => {
    const clients = storage.listClients().map(client => ({
        id: client.id,
        name: client.name,
        redirectUris: client.redirectUris,
        allowedScopes: client.allowedScopes,
        createdAt: client.createdAt,
    }));

    return res.json({ success: true, clients });
});

// Get a specific OAuth client
router.get('/api/clients/:id', requireAuth, requireAdmin, (req: Request, res: Response) => {
    const client = storage.getClient(req.params.id);

    if (!client) {
        return res.status(404).json({
            success: false,
            error: 'Client not found',
        });
    }

    return res.json({
        success: true,
        client: {
            id: client.id,
            name: client.name,
            redirectUris: client.redirectUris,
            allowedScopes: client.allowedScopes,
            createdAt: client.createdAt,
        }
    });
});

// Create a new OAuth client
router.post('/api/clients', requireAuth, requireAdmin, (req: Request, res: Response) => {
    const { name, redirectUris, allowedScopes } = req.body as {
        name: string;
        redirectUris: string[];
        allowedScopes: string[];
    };

    if (!name || !Array.isArray(redirectUris) || !Array.isArray(allowedScopes)) {
        return res.status(400).json({
            success: false,
            error: 'Missing or invalid required fields',
        });
    }

    const client = storage.createClient(name, redirectUris, allowedScopes);

    return res.status(201).json({
        success: true,
        client: {
            id: client.id,
            name: client.name,
            secret: client.secret,  // Only return secret on creation
            redirectUris: client.redirectUris,
            allowedScopes: client.allowedScopes,
            createdAt: client.createdAt,
        }
    });
});

// Delete an OAuth client
router.delete('/api/clients/:id', requireAuth, requireAdmin, (req: Request, res: Response) => {
    const client = storage.getClient(req.params.id);

    if (!client) {
        return res.status(404).json({
            success: false,
            error: 'Client not found',
        });
    }

    const result = storage.deleteClient(req.params.id);

    if (result) {
        return res.json({
            success: true,
            message: 'Client deleted successfully',
        });
    } else {
        return res.status(500).json({
            success: false,
            error: 'Failed to delete client',
        });
    }
});

// Update an OAuth client
router.put('/api/clients/:id', requireAuth, requireAdmin, (req: Request, res: Response) => {
    const client = storage.getClient(req.params.id);

    if (!client) {
        return res.status(404).json({
            success: false,
            error: 'Client not found',
        });
    }

    const { name, redirectUris, allowedScopes } = req.body as {
        name?: string;
        redirectUris?: string[];
        allowedScopes?: string[];
    };

    // Update client properties
    if (name) client.name = name;
    if (redirectUris) client.redirectUris = redirectUris;
    if (allowedScopes) client.allowedScopes = allowedScopes;

    // Store updated client
    storage.clients.set(client.id, client);

    return res.json({
        success: true,
        client: {
            id: client.id,
            name: client.name,
            redirectUris: client.redirectUris,
            allowedScopes: client.allowedScopes,
            createdAt: client.createdAt,
        }
    });
});

export default router;