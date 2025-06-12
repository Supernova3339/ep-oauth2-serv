// Configuration variables with environment fallbacks
import 'dotenv/config'

export const PORT = process.env.PORT || 3000;
export const SESSION_SECRET = process.env.SESSION_SECRET || 'oauth2-server-secret';
export const EASYPANEL_URL = process.env.EASYPANEL_URL || 'http://localhost:3001';
export const ACCESS_TOKEN_EXPIRY = 60 * 60; // 1 hour in seconds
export const REFRESH_TOKEN_EXPIRY = 30 * 24 * 60 * 60; // 30 days in seconds
export const AUTH_CODE_EXPIRY = 10 * 60; // 10 minutes in seconds
export const NODE_ENV = process.env.NODE_ENV || 'development';
export const API_TOKEN = process.env.API_TOKEN || ''; // Easypanel API Token
export const CLIENT_API_KEY = process.env.CLIENT_API_KEY || ''; // API key for client management

// Config validation
if (NODE_ENV === 'production' && SESSION_SECRET === 'oauth2-server-secret') {
    console.warn('WARNING: Using default session secret in production. This is insecure.');
}

if (NODE_ENV === 'production' && !CLIENT_API_KEY) {
    console.warn('WARNING: CLIENT_API_KEY not set. API key authentication will be disabled.');
}

export default {
    PORT,
    SESSION_SECRET,
    EASYPANEL_URL,
    ACCESS_TOKEN_EXPIRY,
    REFRESH_TOKEN_EXPIRY,
    AUTH_CODE_EXPIRY,
    NODE_ENV,
    API_TOKEN,
    CLIENT_API_KEY
};