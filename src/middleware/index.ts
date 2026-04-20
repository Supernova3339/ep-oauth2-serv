import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import * as oauth from '../auth/oauth';
import { CLIENT_API_KEY } from '../config';

export function requireAuth(req: Request, res: Response, next: NextFunction) {
    if (!req.session.user) {
        if (req.method === 'GET') {
            req.session.returnTo = req.originalUrl;
        } else if (req.originalUrl === '/device/verify' && req.method === 'POST') {
            const userCode = req.body.user_code;
            req.session.returnTo = `/device${userCode ? `?user_code=${userCode}` : ''}`;
        }
        return res.redirect('/login');
    }
    next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
    if (!req.session.user?.admin) {
        return res.status(403).render('error', {
            error: 'forbidden',
            error_description: 'Admin access required'
        });
    }
    next();
}

export function requireAuthOrApiKey(req: Request, res: Response, next: NextFunction) {
    const apiKey = req.headers['x-api-key'] as string;
    if (apiKey && CLIENT_API_KEY && apiKey === CLIENT_API_KEY) {
        res.locals.isApiRequest = true;
        res.locals.isAdmin = true;
        return next();
    }

    if (!req.session.user) {
        if (req.headers.accept?.includes('application/json') || req.path.startsWith('/api/')) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required. Provide session authentication or X-API-Key header.'
            });
        }
        if (req.method === 'GET') req.session.returnTo = req.originalUrl;
        return res.redirect('/login');
    }

    res.locals.isApiRequest = false;
    res.locals.isAdmin = req.session.user.admin;
    next();
}

export function requireAdminOrApiKey(req: Request, res: Response, next: NextFunction) {
    if (res.locals.isApiRequest && res.locals.isAdmin) return next();

    if (!req.session.user?.admin) {
        if (req.headers.accept?.includes('application/json') || req.path.startsWith('/api/')) {
            return res.status(403).json({ success: false, error: 'Admin access required' });
        }
        return res.status(403).render('error', {
            error: 'forbidden',
            error_description: 'Admin access required'
        });
    }

    res.locals.isAdmin = true;
    next();
}

export function csrfProtection(req: Request, res: Response, next: NextFunction) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(16).toString('hex');
        return req.session.save((err) => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).render('error', {
                    error: 'server_error',
                    error_description: 'Failed to create CSRF token'
                });
            }
            next();
        });
    }

    if (req.method === 'GET') return next();

    const csrfToken = req.body.csrf_token;
    if (!csrfToken || csrfToken !== req.session.csrfToken) {
        return res.status(403).render('error', {
            error: 'invalid_request',
            error_description: 'CSRF token validation failed'
        });
    }

    const oldToken = req.session.csrfToken;
    req.session.csrfToken = crypto.randomBytes(16).toString('hex');
    req.session.save((err) => {
        if (err) {
            console.error('Error updating CSRF token:', err);
            req.session.csrfToken = oldToken;
        }
        next();
    });
}

export function requireApiAuth(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'unauthorized',
            error_description: 'Missing or invalid token'
        });
    }

    const token = authHeader.substring(7);
    const accessToken = oauth.validateAccessToken(token);
    if (!accessToken) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Token is invalid or expired'
        });
    }

    res.locals.token = accessToken;
    next();
}

export function requestLogger(req: Request, res: Response, next: NextFunction) {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
}

export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
    console.error('Error:', err);

    if (res.headersSent) return next(err);

    let errorMessage = 'An internal server error occurred';
    let errorCode = 'server_error';

    if (err instanceof Error) {
        const statusCode = (err as Error & { statusCode?: number }).statusCode;
        if (statusCode === 400) { errorCode = 'invalid_request'; errorMessage = 'The request was invalid'; }
        else if (statusCode === 401) { errorCode = 'unauthorized'; errorMessage = 'Authentication required'; }
        else if (statusCode === 403) { errorCode = 'forbidden'; errorMessage = "You don't have permission to access this resource"; }
        else if (statusCode === 404) { errorCode = 'not_found'; errorMessage = 'The requested resource was not found'; }

        if (err.message && !err.message.includes('password') &&
            !err.message.includes('token') && !err.message.includes('key')) {
            errorMessage = err.message;
        }
    }

    if (req.path.startsWith('/api/') || req.path.startsWith('/oauth/token')) {
        return res.status(500).json({ error: errorCode, error_description: errorMessage });
    }

    res.status(500).render('error', { error: errorCode, error_description: errorMessage });
}
