#!/usr/bin/env ts-node

import express, { Request, Response } from 'express';
import session from 'express-session';
import axios from 'axios';
import crypto from 'crypto';
import open from 'open';
import fs from 'fs';
import path from 'path';

declare module 'express-session' {
    interface SessionData {
        oauthState?: string;
        oauthNonce?: string;
        accessToken?: string;
        idToken?: string;
        userInfo?: Record<string, unknown>;
    }
}

const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:3000';
const PORT = 8080;
const REDIRECT_URI = `http://localhost:${PORT}/callback`;

function loadConfig() {
    try {
        const raw = fs.readFileSync(path.join(__dirname, 'config.json'), 'utf-8');
        return JSON.parse(raw).openid as { id: string; secret: string };
    } catch {
        return { id: 'openid-example-client', secret: 'openid-example-secret' };
    }
}

const { id: CLIENT_ID, secret: CLIENT_SECRET } = loadConfig();

const app = express();

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views/openid'));

app.get('/', (req: Request, res: Response) => {
    res.render('home', {
        isAuthenticated: !!req.session.userInfo,
        userInfo: req.session.userInfo ?? null,
        accessToken: req.session.accessToken ?? null,
        idToken: req.session.idToken ?? null,
    });
});

app.get('/login', (req: Request, res: Response) => {
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;
    req.session.oauthNonce = nonce;

    req.session.save(err => {
        if (err) return res.status(500).send('Session error');
        const params = new URLSearchParams({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: 'code',
            scope: 'openid profile email',
            state,
            nonce,
        });
        res.redirect(`${SERVER_URL}/oauth/authorize?${params}`);
    });
});

app.get('/callback', async (req: Request, res: Response) => {
    const { code, state, error, error_description } = req.query as Record<string, string>;

    if (error) {
        return res.render('error', { error, error_description: error_description ?? '' });
    }

    if (!state || state !== req.session.oauthState) {
        return res.render('error', {
            error: 'invalid_state',
            error_description: 'State parameter mismatch.'
        });
    }

    try {
        const tokenBody = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT_URI,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
        });

        const { data: tokens } = await axios.post(
            `${SERVER_URL}/oauth/token`,
            tokenBody.toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const { data: userInfo } = await axios.get(`${SERVER_URL}/oauth/userinfo`, {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
        });

        req.session.accessToken = tokens.access_token;
        req.session.idToken = tokens.id_token;
        req.session.userInfo = userInfo;

        req.session.save(err => {
            if (err) return res.status(500).send('Session error');
            res.redirect('/');
        });
    } catch (err) {
        const axErr = axios.isAxiosError(err) ? err : null;
        res.render('error', {
            error: axErr?.response?.data?.error ?? 'server_error',
            error_description: axErr?.response?.data?.error_description
                ?? (err instanceof Error ? err.message : 'Unknown error'),
        });
    }
});

app.get('/logout', (req: Request, res: Response) => {
    req.session.destroy(() => res.redirect('/'));
});

app.listen(PORT, () => {
    console.log(`OpenID Connect example: http://localhost:${PORT}  [${CLIENT_ID}]`);
    console.log(`Auth server: ${SERVER_URL}`);
    open(`http://localhost:${PORT}`);
});
