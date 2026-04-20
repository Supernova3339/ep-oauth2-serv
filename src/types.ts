declare module 'express-session' {
    interface SessionData {
        user?: EasypanelUser;
        authRequest?: {
            response_type: string;
            client_id: string;
            redirect_uri: string;
            scope: string;
            state: string;
            nonce?: string;
        };
        csrfToken?: string;
        twoFactorAuth?: {
            email: string;
            password: string;
            pendingLogin: boolean;
        };
        returnTo?: string;
        successMessage?: string;
        errorMessage?: string;
    }
}

export interface Client {
    id: string;
    name: string;
    secret: string;
    redirectUris: string[];
    allowedScopes: string[];
    createdAt: Date;
    persistent?: boolean;
}

export interface AuthorizationCode {
    code: string;
    clientId: string;
    userId: string;
    redirectUri: string;
    expiresAt: Date;
    scopes: string[];
    nonce?: string;
}

export interface Token {
    accessToken: string;
    refreshToken: string;
    clientId: string;
    userId: string;
    scopes: string[];
    expiresAt: Date;
}

export interface EasypanelUser {
    id: string;
    email: string;
    admin: boolean;
}

export interface LoginResponse {
    success: boolean;
    user?: EasypanelUser;
    twoFactorRequired?: boolean;
    error?: string;
    token?: string;
}
