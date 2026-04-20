import { Router, Request, Response } from 'express';
import path from 'path';
import { csrfProtection, requireAuth } from '../middleware';
import { validateEasypanelCredentials } from '../auth/easypanel';
import { EASYPANEL_URL } from '../config';

const router = Router();

router.get('/api/me', (req: Request, res: Response) => {
    if (!req.session.user) return res.status(401).json({ error: 'unauthorized' });
    return res.json({ user: req.session.user, easypanelUrl: EASYPANEL_URL });
});

router.get('/api/config', (_req: Request, res: Response) => {
    return res.json({ easypanelUrl: EASYPANEL_URL });
});

router.get('/api/csrf', csrfProtection, (req: Request, res: Response) => {
    return res.json({ token: req.session.csrfToken });
});

router.post('/login', csrfProtection, async (req: Request, res: Response) => {
    const { email, password, rememberMe } = req.body as { email: string; password: string; rememberMe?: boolean };
    const loginResult = await validateEasypanelCredentials(email, password);

    if (loginResult.twoFactorRequired) {
        req.session.twoFactorAuth = { email, password, pendingLogin: true };
        return req.session.save(() => res.json({ twoFactorRequired: true }));
    }

    if (!loginResult.success || !loginResult.user) {
        return res.status(401).json({ error: loginResult.error || 'Invalid credentials' });
    }

    if (rememberMe) {
        req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    }

    req.session.user = loginResult.user;
    return req.session.save(() => res.json({ success: true, user: loginResult.user }));
});

router.post('/twoFactor', csrfProtection, async (req: Request, res: Response) => {
    const { code } = req.body as { code: string };

    if (!req.session.twoFactorAuth?.pendingLogin) {
        return res.status(400).json({ error: 'No pending two-factor authentication' });
    }

    const { email, password } = req.session.twoFactorAuth;
    delete req.session.twoFactorAuth;

    try {
        const loginResult = await validateEasypanelCredentials(email, password, code);

        if (!loginResult.success || !loginResult.user) {
            if (loginResult.twoFactorRequired) {
                req.session.twoFactorAuth = { email, password, pendingLogin: true };
                return req.session.save(() =>
                    res.status(401).json({ error: 'Invalid verification code. Please try again.' })
                );
            }
            return res.status(401).json({ error: loginResult.error || 'Authentication failed' });
        }

        req.session.user = loginResult.user;
        return req.session.save(() => res.json({ success: true, user: loginResult.user }));
    } catch {
        return res.status(500).json({ error: 'An error occurred during verification.' });
    }
});

router.post('/logout', (req: Request, res: Response) => {
    req.session.destroy((err) => {
        if (err) console.error('Error destroying session:', err);
        res.json({ success: true });
    });
});

router.get('/openapi.json', requireAuth, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, '../../openapi.json'));
});

export default router;
