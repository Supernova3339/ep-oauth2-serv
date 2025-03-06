// src/routes/test.ts
import { Router, Request, Response } from 'express';
import { requireAuth, requireAdmin } from '../middleware';
import * as storage from '../storage/lmdb';
import * as dbHelpers from '../storage/db-helpers';

const router = Router();

// Admin-only database list page
router.get('/test/db-list', requireAuth, requireAdmin, async (req: Request, res: Response) => {
    try {
        // Gather data from all databases
        const data = {
            clients: storage.listClients(),
            deviceCodes: await dbHelpers.getAllDeviceCodes(),
            authorizationCodes: await dbHelpers.getAllAuthorizationCodes(),
            tokens: await dbHelpers.getAllTokens(),
            refreshTokens: await dbHelpers.getAllRefreshTokens()
        };

        // Render the admin page with data
        res.render('admin/db-list', {
            user: req.session.user,
            data
        });
    } catch (error) {
        console.error('Error loading database data:', error);
        res.status(500).render('error', {
            error: 'server_error',
            error_description: 'Failed to load database information'
        });
    }
});

export default router;