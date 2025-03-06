import { Router, Request, Response } from 'express';
import { requireAuth, requireAdmin, csrfProtection } from '../middleware';
import * as storage from '../storage/lmdb';

const router = Router();

// Admin dashboard page
router.get('/admin', requireAuth, requireAdmin, (req: Request, res: Response) => {
    res.redirect('/admin/clients');
});

export default router;

// Client management page
router.get('/admin/clients', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    const clients = storage.listClients();

    // Check for flash messages in session
    const success = req.session.successMessage || null;
    const error = req.session.errorMessage || null;

    // Clear flash messages after use
    delete req.session.successMessage;
    delete req.session.errorMessage;

    res.render('admin/clients', {
        clients,
        csrfToken: req.session.csrfToken,
        success,
        error
    });
});

// Create a new client
router.post('/admin/clients', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        // Extract client data from request body
        const { name, redirectUris, scopes, persistent } = req.body;

        // Validate required fields
        if (!name || !redirectUris) {
            req.session.errorMessage = 'Client name and redirect URIs are required';
            return res.redirect('/admin/clients');
        }

        // Process redirect URIs (split by newline)
        const uris = typeof redirectUris === 'string'
            ? redirectUris.split('\n').map(uri => uri.trim()).filter(uri => uri)
            : redirectUris;

        // Process scopes (ensure it's an array)
        const scopesArray = Array.isArray(scopes) ? scopes : [scopes].filter(Boolean);

        // Create the client
        const client = storage.createClient(
            name,
            uris,
            scopesArray,
            persistent === 'true'
        );

        // Render the client secret page to show the credentials
        return res.render('admin/client-secret', {
            client
        });
    } catch (error) {
        console.error('Error creating client:', error);
        req.session.errorMessage = `Failed to create client: ${error instanceof Error ? error.message : 'Unknown error'}`;
        return res.redirect('/admin/clients');
    }
});

// Update an existing client
router.put('/admin/clients/:id', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const clientId = req.params.id;
        const { name, redirectUris, scopes, persistent } = req.body;

        // Validate required fields
        if (!name || !redirectUris) {
            return res.status(400).json({
                success: false,
                message: 'Client name and redirect URIs are required'
            });
        }

        // Process redirect URIs (split by newline)
        const uris = typeof redirectUris === 'string'
            ? redirectUris.split('\n').map(uri => uri.trim()).filter(uri => uri)
            : redirectUris;

        // Process scopes (ensure it's an array)
        const scopesArray = Array.isArray(scopes) ? scopes : [scopes].filter(Boolean);

        // Update the client
        const updatedClient = storage.updateClient(clientId, {
            name,
            redirectUris: uris,
            allowedScopes: scopesArray,
            persistent: persistent === 'true'
        });

        if (!updatedClient) {
            return res.status(404).json({
                success: false,
                message: `Client with ID "${clientId}" not found`
            });
        }

        // Set success message
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

// Delete a client
router.delete('/admin/clients/:id', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const clientId = req.params.id;

        // Get client details before deletion (for the success message)
        const client = storage.getClient(clientId);

        if (!client) {
            return res.status(404).json({
                success: false,
                message: `Client with ID "${clientId}" not found`
            });
        }

        // Delete the client
        const result = storage.deleteClient(clientId);

        if (!result) {
            return res.status(500).json({
                success: false,
                message: 'Failed to delete client'
            });
        }

        // Set success message
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

// Get client details
router.get('/admin/clients/:id', requireAuth, requireAdmin, (req: Request, res: Response) => {
    try {
        const clientId = req.params.id;
        const client = storage.getClient(clientId);

        if (!client) {
            return res.status(404).json({
                success: false,
                message: `Client with ID "${clientId}" not found`
            });
        }

        // Return client details (excluding the secret for security)
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

// Generate a new client secret
router.post('/admin/clients/:id/secret', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const clientId = req.params.id;

        // Generate a random string for the new secret
        const newSecret = Array.from(
            { length: 32 },
            () => Math.floor(Math.random() * 36).toString(36)
        ).join('');

        // Update the client with the new secret
        const updatedClient = storage.updateClient(clientId, {
            secret: newSecret
        });

        if (!updatedClient) {
            return res.status(404).json({
                success: false,
                message: `Client with ID "${clientId}" not found`
            });
        }

        // Check if request wants JSON response
        const acceptJson = req.headers.accept === 'application/json';

        if (acceptJson) {
            // Return the new secret as JSON
            return res.json({
                success: true,
                clientId: updatedClient.id,
                clientName: updatedClient.name,
                clientSecret: newSecret
            });
        } else {
            // Render the client secret page
            return res.render('admin/client-secret', {
                client: {
                    ...updatedClient,
                    secret: newSecret // Include the secret for display
                }
            });
        }
    } catch (error) {
        console.error('Error generating new client secret:', error);
        req.session.errorMessage = `Failed to generate new client secret: ${error instanceof Error ? error.message : 'Unknown error'}`;
        return res.redirect('/admin/clients');
    }
});

// Show page for generating a new client secret
router.get('/admin/clients/:id/secret', requireAuth, requireAdmin, csrfProtection, (req: Request, res: Response) => {
    try {
        const clientId = req.params.id;
        const client = storage.getClient(clientId);

        if (!client) {
            req.session.errorMessage = `Client with ID "${clientId}" not found`;
            return res.redirect('/admin/clients');
        }

        // Render confirmation page
        return res.render('admin/regenerate-secret', {
            client: {
                id: client.id,
                name: client.name
            },
            csrfToken: req.session.csrfToken
        });
    } catch (error) {
        console.error('Error loading client secret page:', error);
        req.session.errorMessage = `Failed to load client secret page: ${error instanceof Error ? error.message : 'Unknown error'}`;
        return res.redirect('/admin/clients');
    }
});