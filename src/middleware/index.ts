import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import * as oauth from '../auth/oauth';

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
 * Generates and verifies CSRF tokens
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction) {
    // Generate a CSRF token if one doesn't exist
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(16).toString('hex');
    }

    // For GET requests, just continue
    if (req.method === 'GET') {
        return next();
    }

    // For POST/PUT/DELETE, validate CSRF token
    const csrfToken = req.body.csrf_token;

    if (!csrfToken || csrfToken !== req.session.csrfToken) {
        return res.status(403).render('error', {
            error: 'invalid_request',
            error_description: 'CSRF token validation failed'
        });
    }

    // Generate a new token for next request
    req.session.csrfToken = crypto.randomBytes(16).toString('hex');
    next();
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