import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import * as oauth from '../auth/oauth';
import { CLIENT_API_KEY } from '../config';

/**
 * Ensures the user is authenticated
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
    if (!req.session.user) {
        // Store the original URL for redirection after login
        if (req.method === 'GET') {
            // Only store GET requests as returnTo URLs
            req.session.returnTo = req.originalUrl;
        } else if (req.originalUrl === '/device/verify' && req.method === 'POST') {
            // Special case for device verification to redirect back to the device page
            // Store user_code if available
            const userCode = req.body.user_code;
            const userCodeParam = userCode ? `?user_code=${userCode}` : '';
            req.session.returnTo = `/device${userCodeParam}`;
        }
        return res.redirect('/login');
    }

    next();
}

/**
 * Ensures the user is an admin
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction) {
    if (!req.session.user || !req.session.user.admin) {
        return res.status(403).render('error', {
            error: 'forbidden',
            error_description: 'Admin access required'
        });
    }

    next();
}

/**
 * Enhanced authentication middleware that supports both session-based auth and API key auth
 */
export function requireAuthOrApiKey(req: Request, res: Response, next: NextFunction) {
    // Check for API key authentication first
    const apiKey = req.headers['x-api-key'] as string;

    if (apiKey && CLIENT_API_KEY && apiKey === CLIENT_API_KEY) {
        // API key is valid, mark this as an API request and continue
        res.locals.isApiRequest = true;
        res.locals.isAdmin = true; // API key grants admin access
        return next();
    }

    // Fall back to session-based authentication
    if (!req.session.user) {
        // For API requests (determined by Accept header or path), return JSON error
        if (req.headers.accept?.includes('application/json') || req.path.startsWith('/api/')) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required. Provide session authentication or X-API-Key header.'
            });
        }

        // For web requests, redirect to login
        if (req.method === 'GET') {
            req.session.returnTo = req.originalUrl;
        }
        return res.redirect('/login');
    }

    // Session user exists, mark as web request
    res.locals.isApiRequest = false;
    res.locals.isAdmin = req.session.user.admin;
    next();
}

/**
 * Requires admin access (via session or API key)
 */
export function requireAdminOrApiKey(req: Request, res: Response, next: NextFunction) {
    // Check if already authenticated via API key
    if (res.locals.isApiRequest && res.locals.isAdmin) {
        return next();
    }

    // Check session-based admin access
    if (!req.session.user || !req.session.user.admin) {
        if (req.headers.accept?.includes('application/json') || req.path.startsWith('/api/')) {
            return res.status(403).json({
                success: false,
                error: 'Admin access required'
            });
        }

        return res.status(403).render('error', {
            error: 'forbidden',
            error_description: 'Admin access required'
        });
    }

    res.locals.isAdmin = true;
    next();
}

/**
 * Generates and verifies CSRF tokens
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction) {
    // Debug session information
    // console.log('Session ID:', req.sessionID);
    // console.log('Session has CSRF token:', !!req.session.csrfToken);
    // console.log('Session cookie:', req.headers.cookie);

    // Generate a CSRF token if one doesn't exist
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(16).toString('hex');

        // Force session save to ensure token is stored before proceeding
        return req.session.save((err) => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).render('error', {
                    error: 'server_error',
                    error_description: 'Failed to create CSRF token'
                });
            }

            // console.log('New CSRF token generated:', req.session.csrfToken);
            next();
        });
    }

    // For GET requests, just continue
    if (req.method === 'GET') {
        return next();
    }

    // For POST/PUT/DELETE, validate CSRF token
    const csrfToken = req.body.csrf_token;

    // console.log('Received CSRF token:', csrfToken);
    // console.log('Expected CSRF token:', req.session.csrfToken);

    if (!csrfToken || csrfToken !== req.session.csrfToken) {
        return res.status(403).render('error', {
            error: 'invalid_request',
            error_description: 'CSRF token validation failed'
        });
    }

    // Generate a new token for next request
    const oldToken = req.session.csrfToken;
    req.session.csrfToken = crypto.randomBytes(16).toString('hex');

    // Force session save to ensure token update is stored
    req.session.save((err) => {
        if (err) {
            console.error('Error updating CSRF token:', err);
            // Continue anyway, using the old token is better than failing
            req.session.csrfToken = oldToken;
        }
        next();
    });
}

/**
 * Authentication middleware for API endpoints using Bearer tokens
 */
export function requireApiAuth(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
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

    // Store token info for use in route handlers
    res.locals.token = accessToken;
    next();
}

/**
 * Logs request information
 */
export function requestLogger(req: Request, res: Response, next: NextFunction) {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
}

/**
 * Global error handler
 */
export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
    console.error('Error:', err);

    // Check if headers have already been sent
    if (res.headersSent) {
        return next(err);
    }

    // Extract a user-friendly error message
    let errorMessage = 'An internal server error occurred';
    let errorCode = 'server_error';

    // Try to extract more specific error information if available
    if (err instanceof Error) {
        // Check for common error types and extract appropriate messages
        if ('statusCode' in err && typeof (err as any).statusCode === 'number') {
            // Handle HTTP errors
            const statusCode = (err as any).statusCode;

            if (statusCode === 400) {
                errorCode = 'invalid_request';
                errorMessage = 'The request was invalid';
            } else if (statusCode === 401) {
                errorCode = 'unauthorized';
                errorMessage = 'Authentication required';
            } else if (statusCode === 403) {
                errorCode = 'forbidden';
                errorMessage = 'You don\'t have permission to access this resource';
            } else if (statusCode === 404) {
                errorCode = 'not_found';
                errorMessage = 'The requested resource was not found';
            }
        }

        // Use the error message if available and not containing sensitive info
        if (err.message && !err.message.includes('password') &&
            !err.message.includes('token') && !err.message.includes('key')) {
            errorMessage = err.message;
        }
    }

    // API error response
    if (req.path.startsWith('/api/') || req.path.startsWith('/oauth/token')) {
        return res.status(500).json({
            error: errorCode,
            error_description: errorMessage
        });
    }

    // UI error response
    res.status(500).render('error', {
        error: errorCode,
        error_description: errorMessage
    });
}