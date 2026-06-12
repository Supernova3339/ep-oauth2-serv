import { Store, SessionData } from 'express-session';
import { sessionsDb } from './lmdb';

const DEFAULT_MAX_AGE = 24 * 60 * 60 * 1000;

export class LmdbSessionStore extends Store {
    get(sid: string, callback: (err: unknown, session?: SessionData | null) => void): void {
        try {
            const record = sessionsDb.get(sid);
            if (!record || record.expires < Date.now()) return callback(null, null);
            callback(null, record.session as SessionData);
        } catch (err) {
            callback(err);
        }
    }

    set(sid: string, session: SessionData, callback?: (err?: unknown) => void): void {
        const maxAge = session.cookie?.maxAge ?? DEFAULT_MAX_AGE;
        const expires = Date.now() + maxAge;
        sessionsDb.put(sid, { session, expires }).then(
            () => callback?.(),
            (err) => callback?.(err)
        );
    }

    destroy(sid: string, callback?: (err?: unknown) => void): void {
        sessionsDb.remove(sid).then(
            () => callback?.(),
            (err) => callback?.(err)
        );
    }

    touch(sid: string, session: SessionData, callback?: () => void): void {
        this.set(sid, session, callback);
    }
}
