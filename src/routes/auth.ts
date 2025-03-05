import { Router, Request, Response } from 'express';
import { csrfProtection } from '../middleware';
import { validateEasypanelCredentials } from '../auth/easypanel';

const router = Router();

// Login page
router.get('/login', csrfProtection, (req: Request, res: Response) => {
    // If user is already logged in, redirect to home
    if (req.session.user) {
        return res.redirect('/');
    }

    res.render('login', {
        csrfToken: req.session.csrfToken,
        error: null
    });
});

// Login form submission
router.post('/login', csrfProtection, async (req: Request, res: Response) => {
    const { email, password } = req.body as { email: string; password: string; };

    // Validate credentials with Easypanel
    const loginResult = await validateEasypanelCredentials(email, password);

    if (loginResult.twoFactorRequired) {
        // Store email and password in session for 2FA verification
        req.session.twoFactorAuth = {
            email,
            password,
            pendingLogin: true
        };

        // Redirect to 2FA page
        return res.render('twoFactor', {
            csrfToken: req.session.csrfToken,
            email,
            password: '********', // Don't send actual password back to client
            error: null
        });
    }

    if (!loginResult.success || !loginResult.user) {
        return res.render('login', {
            csrfToken: req.session.csrfToken,
            error: loginResult.error || 'Invalid credentials'
        });
    }

    // Login successful, store user in session
    req.session.user = loginResult.user;

    // Check if there's a returnTo URL
    const returnTo = req.session.returnTo;
    delete req.session.returnTo;

    // Redirect to appropriate page
    if (returnTo) {
        return res.redirect(returnTo);
    } else {
        return res.redirect('/');
    }
});

// Two-factor authentication form submission
router.post('/twoFactor', csrfProtection, async (req: Request, res: Response) => {
    const { code } = req.body as { code: string; };

    // Make sure we have pending 2FA
    if (!req.session.twoFactorAuth || !req.session.twoFactorAuth.pendingLogin) {
        return res.redirect('/login');
    }

    const { email, password } = req.session.twoFactorAuth;

    try {
        // Validate credentials with 2FA code
        const loginResult = await validateEasypanelCredentials(email, password, code);

        // Clear 2FA data from session, regardless of outcome
        delete req.session.twoFactorAuth;

        if (!loginResult.success || !loginResult.user) {
            // If 2FA still required, it's an invalid code
            if (loginResult.twoFactorRequired) {
                return res.render('twoFactor', {
                    csrfToken: req.session.csrfToken,
                    email,
                    password: '********',
                    error: 'Invalid verification code. Please try again.'
                });
            }

            // Format the error message to be user-friendly
            const errorMessage = loginResult.error || 'Authentication failed';

            return res.render('login', {
                csrfToken: req.session.csrfToken,
                error: errorMessage
            });
        }

        // Login successful, store user in session
        req.session.user = loginResult.user;

        // Check if there's a returnTo URL
        const returnTo = req.session.returnTo;
        delete req.session.returnTo;

        // Redirect to appropriate page
        if (returnTo) {
            return res.redirect(returnTo);
        } else {
            return res.redirect('/');
        }
    } catch (error) {
        console.error('Error during two-factor authentication:', error);

        return res.render('twoFactor', {
            csrfToken: req.session.csrfToken,
            email,
            password: '********',
            error: 'An error occurred during verification. Please try again.'
        });
    }
});

// Logout
router.get('/logout', (req: Request, res: Response) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

export default router;