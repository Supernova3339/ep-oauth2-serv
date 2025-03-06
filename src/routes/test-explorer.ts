// src/routes/test-explorer.ts
import { Router, Request, Response } from 'express';
import { requireAuth, requireAdmin } from '../middleware';
import * as dbExplorer from '../storage/db-explorer';

const router = Router();

// Admin-only database explorer
router.get('/test/db-explorer', requireAuth, requireAdmin, async (req: Request, res: Response) => {
    try {
        // Dynamically explore all databases with error handling
        let dbData;

        try {
            dbData = await dbExplorer.exploreAllDatabases();
        } catch (error) {
            console.error('Failed to explore databases:', error);
            dbData = {}; // Provide empty data on error
        }

        // Render the view with the discovered data (or empty data on error)
        res.render('admin/db-explorer', {
            user: req.session.user,
            databases: dbData,
            title: 'Database Explorer',
            error: dbData && Object.keys(dbData).length === 0 ? 'Failed to explore databases' : null
        });
    } catch (viewError) {
        console.error('Error rendering database explorer view:', viewError);
        res.status(500).render('error', {
            error: 'server_error',
            error_description: 'Failed to render database explorer'
        });
    }
});

// View a specific database in detail
router.get('/test/db-explorer/:dbName', requireAuth, requireAdmin, async (req: Request, res: Response) => {
    try {
        const { dbName } = req.params;

        // Get detailed info about this specific database
        const dbInfo = await dbExplorer.exploreDatabaseByName(dbName);

        // Try to guess the schema
        let schemaInfo;
        try {
            schemaInfo = await dbExplorer.guessDbSchema(dbName);
        } catch (schemaError) {
            console.error('Error guessing schema:', schemaError);
            schemaInfo = {
                name: dbName,
                count: dbInfo.count || 0,
                sampleSize: 0,
                inferredSchema: {},
                isConsistent: false,
                error: `Error: ${schemaError instanceof Error ? schemaError.message : String(schemaError)}`
            };
        }

        // Check for errors and create an error view if needed
        if (!dbInfo || (dbInfo.error && dbInfo.count === 0)) {
            return res.status(404).render('error', {
                error: 'not_found',
                error_description: `Database '${dbName}' not found or cannot be read: ${dbInfo?.error || 'Unknown error'}`
            });
        }

        // Render the detailed view
        res.render('admin/db-detail', {
            user: req.session.user,
            dbInfo,
            schemaInfo,
            title: `Database: ${dbName}`,
            error: dbInfo.error || schemaInfo.error || null
        });
    } catch (error) {
        console.error('Error viewing database:', error);
        res.status(500).render('error', {
            error: 'server_error',
            error_description: 'Failed to load database details'
        });
    }
});

// View a specific entry in a database
router.get('/test/db-explorer/:dbName/entry/:key', requireAuth, requireAdmin, async (req: Request, res: Response) => {
    try {
        const { dbName, key } = req.params;

        // Get the specific entry with error handling
        let entry;
        try {
            entry = await dbExplorer.getEntryByKey(dbName, key);
        } catch (entryError) {
            console.error('Error retrieving entry:', entryError);
            entry = `Error: ${entryError instanceof Error ? entryError.message : String(entryError)}`;
        }

        // Check if entry exists
        if (!entry || (typeof entry === 'string' && entry.startsWith('Error:'))) {
            return res.status(404).render('error', {
                error: 'not_found',
                error_description: `Entry with key '${key}' not found in database '${dbName}' or cannot be read: ${
                    typeof entry === 'string' && entry.startsWith('Error:') ? entry : 'Unknown error'
                }`
            });
        }

        // Render the entry detail view
        res.render('admin/entry-detail', {
            user: req.session.user,
            dbName,
            key,
            entry,
            title: `Entry ${key} in ${dbName}`,
            error: null
        });
    } catch (error) {
        console.error('Error viewing entry:', error);
        res.status(500).render('error', {
            error: 'server_error',
            error_description: 'Failed to load entry details'
        });
    }
});

export default router;