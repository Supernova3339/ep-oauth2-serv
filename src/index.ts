import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import path from 'path';
import {EASYPANEL_URL, NODE_ENV, PORT, SESSION_SECRET} from './config';
import {errorHandler, requestLogger} from './middleware';
import authRoutes from './routes/auth';
import oauthRoutes from './routes/oauth';
import apiRoutes from './routes/api';
import testRoutes from './routes/test';
import dbExplorerRoutes from './routes/test-explorer';
import adminRoutes from './routes/admin';

// Import the LMDB storage instead of memory storage
import * as storage from './storage/lmdb';

// Initialize Express app
const app = express();

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Middleware
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(
    session({
        secret: SESSION_SECRET,
        resave: true,  // Changed to true to ensure session is always saved
        saveUninitialized: true, // Changed to true to save new sessions
        cookie: {
            secure: NODE_ENV === 'production' && process.env.ENABLE_SECURE_COOKIE === 'true', // Only use secure cookies when explicitly enabled
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            sameSite: 'lax' // Helps with CSRF protection while allowing redirects
        }
    })
);
app.use(requestLogger);

// Initialize test client in development
if (NODE_ENV == 'development') {
    storage.initializeTestClient();
}

// Routes
app.use(authRoutes);
app.use(oauthRoutes);
app.use(apiRoutes)
app.use(testRoutes);
app.use(dbExplorerRoutes);
app.use(adminRoutes);


// Home page
app.get('/', (req, res) => {
    res.render('home', {
        user: req.session.user || null
    });
});

// Error handler
app.use(errorHandler);

// Start the server
app.listen(PORT, () => {
    console.log(`\nOAuth2 server running on port ${PORT}`);
    console.log(`Easypanel URL: ${EASYPANEL_URL}`);
    console.log(`Environment: ${NODE_ENV}`);
    console.log('\nAvailable endpoints:');
    console.log('- Discovery: GET /.well-known/openid-configuration');
    console.log('- Authorization: GET /oauth/authorize');
    console.log('- Token: POST /oauth/token');
    console.log('- Introspection: POST /oauth/introspect');
    console.log('- UserInfo: GET /oauth/userinfo');
    console.log('- JWKS: GET /oauth/jwks');
    console.log('- Revocation: POST /oauth/revoke');
    console.log('- Device Authorization: POST /oauth/device');
    console.log('- Client Management: /api/clients\n');
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: shutting down');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT signal received: shutting down');
    process.exit(0);
});