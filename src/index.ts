import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import path from 'path';
import { EASYPANEL_URL, NODE_ENV, PORT, SESSION_SECRET } from './config';
import { errorHandler, requestLogger } from './middleware';
import authRoutes from './routes/auth';
import oauthRoutes from './routes/oauth';
import apiRoutes from './routes/api';
import * as storage from './storage/lmdb';

const app = express();

if (NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

app.use(express.static(path.join(__dirname, '../public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        proxy: NODE_ENV === 'production',
        cookie: {
            secure: NODE_ENV === 'production',
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: 'lax'
        }
    })
);
app.use(requestLogger);

if (NODE_ENV === 'development') {
    storage.initializeTestClient();
}

app.use(authRoutes);
app.use(oauthRoutes);
app.use(apiRoutes);

const spaPath = path.join(__dirname, '../public/index.html');

app.get('*', (_req, res, next) => {
    res.sendFile(spaPath, err => { if (err) next(); });
});

app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`OAuth2 server running on port ${PORT} (${NODE_ENV})`);
    console.log(`Easypanel: ${EASYPANEL_URL}`);
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
