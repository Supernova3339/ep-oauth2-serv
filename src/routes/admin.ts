import crypto from 'crypto';
import { Router, Request, Response } from 'express';
import { requireAuth, requireAdmin, csrfProtection } from '../middleware';
import * as storage from '../storage/lmdb';

const router = Router();

router.get('/admin', requireAuth, requireAdmin, (req: Request, res: Response) => {
    res.redirect('/admin/clients');
});

router.get('/admin/clients', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    const clients = storage.listClients();
    const success = req.session.successMessage || null;
    const error = req.session.errorMessage || null;
    delete req.session.successMessage;
    delete req.session.errorMessage;
    res.render('admin/clients', { clients, csrfToken: req.session.csrfToken, success, error });
});

router.post('/admin/clients', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const { name, redirectUris, scopes, persistent } = req.body;

        if (!name || !redirectUris) {
            req.session.errorMessage = 'Client name and redirect URIs are required';
            return res.redirect('/admin/clients');
        }

        const uris = typeof redirectUris === 'string'
            ? redirectUris.split('\n').map((u: string) => u.trim()).filter(Boolean)
            : redirectUris;
        const scopesArray = Array.isArray(scopes) ? scopes : [scopes].filter(Boolean);

        const client = storage.createClient(name, uris, scopesArray, persistent === 'true');
        return res.render('admin/client-secret', { client });
    } catch (error) {
        console.error('Error creating client:', error);
        req.session.errorMessage = `Failed to create client: ${error instanceof Error ? error.message : 'Unknown error'}`;
        return res.redirect('/admin/clients');
    }
});

router.put('/admin/clients/:id', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const { name, redirectUris, scopes, persistent } = req.body;

        if (!name || !redirectUris) {
            return res.status(400).json({ success: false, message: 'Client name and redirect URIs are required' });
        }

        const uris = typeof redirectUris === 'string'
            ? redirectUris.split('\n').map((u: string) => u.trim()).filter(Boolean)
            : redirectUris;
        const scopesArray = Array.isArray(scopes) ? scopes : [scopes].filter(Boolean);

        const updatedClient = storage.updateClient(req.params.id, {
            name,
            redirectUris: uris,
            allowedScopes: scopesArray,
            persistent: persistent === 'true'
        });

        if (!updatedClient) {
            return res.status(404).json({ success: false, message: `Client with ID "${req.params.id}" not found` });
        }

        req.session.successMessage = `Client "${name}" updated successfully`;
        return res.status(200).json({ success: true });
    } catch (error) {
        console.error('Error updating client:', error);
        return res.status(500).json({
            success: false,
            message: `Failed to update client: ${error instanceof Error ? error.message : 'Unknown error'}`
        });
    }
});

router.delete('/admin/clients/:id', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const client = storage.getClient(req.params.id);
        if (!client) {
            return res.status(404).json({ success: false, message: `Client with ID "${req.params.id}" not found` });
        }

        if (!storage.deleteClient(req.params.id)) {
            return res.status(500).json({ success: false, message: 'Failed to delete client' });
        }

        req.session.successMessage = `Client "${client.name}" deleted successfully`;
        return res.status(200).json({ success: true });
    } catch (error) {
        console.error('Error deleting client:', error);
        return res.status(500).json({
            success: false,
            message: `Failed to delete client: ${error instanceof Error ? error.message : 'Unknown error'}`
        });
    }
});

router.get('/admin/clients/:id', requireAuth, requireAdmin, (req: Request, res: Response) => {
    try {
        const client = storage.getClient(req.params.id);
        if (!client) {
            return res.status(404).json({ success: false, message: `Client with ID "${req.params.id}" not found` });
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
    } catch (error) {
        console.error('Error getting client details:', error);
        return res.status(500).json({
            success: false,
            message: `Failed to get client details: ${error instanceof Error ? error.message : 'Unknown error'}`
        });
    }
});

router.post('/admin/clients/:id/secret', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const newSecret = crypto.randomBytes(32).toString('hex');
        const updatedClient = storage.updateClient(req.params.id, { secret: newSecret });

        if (!updatedClient) {
            return res.status(404).json({ success: false, message: `Client with ID "${req.params.id}" not found` });
        }

        if (req.headers.accept === 'application/json') {
            return res.json({
                success: true,
                clientId: updatedClient.id,
                clientName: updatedClient.name,
                clientSecret: newSecret
            });
        }

        return res.render('admin/client-secret', { client: { ...updatedClient, secret: newSecret } });
    } catch (error) {
        console.error('Error generating new client secret:', error);
        req.session.errorMessage = `Failed to generate new client secret: ${error instanceof Error ? error.message : 'Unknown error'}`;
        return res.redirect('/admin/clients');
    }
});

router.get('/admin/clients/:id/secret', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const client = storage.getClient(req.params.id);
        if (!client) {
            req.session.errorMessage = `Client with ID "${req.params.id}" not found`;
            return res.redirect('/admin/clients');
        }
        return res.render('admin/regenerate-secret', {
            client: { id: client.id, name: client.name },
            csrfToken: req.session.csrfToken
        });
    } catch (error) {
        console.error('Error loading client secret page:', error);
        req.session.errorMessage = `Failed to load client secret page: ${error instanceof Error ? error.message : 'Unknown error'}`;
        return res.redirect('/admin/clients');
    }
});

export default router;
