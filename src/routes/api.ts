import { Router, Request, Response } from 'express';
import { requireAuth, requireAdmin } from '../middleware';
// Update to use LMDB storage
import * as storage from '../storage/lmdb';

const router = Router();

// List all OAuth clients
router.get('/api/clients', requireAuth, requireAdmin, (req: Request, res: Response) => {
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
            persistent: client.persistent || false
        }
    });
});

// Create a new OAuth client
router.post('/api/clients', requireAuth, requireAdmin, (req: Request, res: Response) => {
    const { name, redirectUris, allowedScopes, persistent } = req.body as {
        name: string;
        redirectUris: string[];
        allowedScopes: string[];
        persistent?: boolean;
    };

    if (!name || !Array.isArray(redirectUris) || !Array.isArray(allowedScopes)) {
        return res.status(400).json({
            success: false,
            error: 'Missing or invalid required fields',
        });
    }

    const client = storage.createClient(
        name,
        redirectUris,
        allowedScopes,
        !!persistent // Convert to boolean
    );

    return res.status(201).json({
        success: true,
        client: {
            id: client.id,
            name: client.name,
            secret: client.secret,  // Only return secret on creation
            redirectUris: client.redirectUris,
            allowedScopes: client.allowedScopes,
            createdAt: client.createdAt,
            persistent: client.persistent || false
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

    const { name, redirectUris, allowedScopes, persistent } = req.body as {
        name?: string;
        redirectUris?: string[];
        allowedScopes?: string[];
        persistent?: boolean;
    };

    // Update client using the new updateClient function
    const updatedClient = storage.updateClient(client.id, {
        name,
        redirectUris,
        allowedScopes,
        persistent: persistent !== undefined ? persistent : client.persistent
    });

    if (!updatedClient) {
        return res.status(500).json({
            success: false,
            error: 'Failed to update client'
        });
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

export default router;