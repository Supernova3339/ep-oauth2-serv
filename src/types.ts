// Extend Express Session
declare module 'express-session' {
    interface SessionData {
        user?: EasypanelUser;
        authRequest?: {
            response_type: string | any;
            client_id: string | any;
            redirect_uri: string | any;
            scope: string | any;
            state: string | any;
            nonce?: string | any; // Add nonce for OpenID Connect
        };
        csrfToken?: string;
        twoFactorAuth?: {
            email: string;
            password: string;
            pendingLogin: boolean;
        };
        returnTo?: string; // URL to return to after authentication
    }
}

// OAuth2 Client
export interface Client {
    id: string;
    name: string;
    secret: string;
    redirectUris: string[];
    allowedScopes: string[];
    createdAt: Date;
    persistent?: boolean; // Whether the client should be saved to disk
}

// Authorization Code
export interface AuthorizationCode {
    code: string;
    clientId: string;
    userId: string;
    redirectUri: string;
    expiresAt: Date;
    scopes: string[];
    nonce?: string; // OpenID Connect needs this
}

// Access Token
export interface Token {
    accessToken: string;
    refreshToken: string;
    clientId: string;
    userId: string;
    scopes: string[];
    expiresAt: Date;
}

// Easypanel User
export interface EasypanelUser {
    id: string;
    email: string;
    admin: boolean;
}

// Login Response
export interface LoginResponse {
    success: boolean;
    user?: EasypanelUser;
    twoFactorRequired?: boolean;
    error?: string;
    token?: string;
}

// API Responses
export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
}