const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getDb, initSchema } = require('./_db');

const JWT_SECRET = process.env.JWT_SECRET || 'job-tracker-secret-change-in-production';

// Check environment variables at startup
if (!process.env.TURSO_DATABASE_URL) {
    console.error('TURSO_DATABASE_URL is not set!');
}
if (!process.env.TURSO_AUTH_TOKEN) {
    console.error('TURSO_AUTH_TOKEN is not set!');
}

function generateId() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

module.exports = async (req, res) => {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.status(200).end();

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        console.log('Auth: Starting...');
        console.log('Auth: initSchema...');
        await initSchema();
        console.log('Auth: getDb...');
        const db = getDb();
        console.log('Auth: parsing body...');
        const { username, pin, action } = req.body;
        console.log('Auth: got username:', username, 'action:', action);

        if (!username || !pin) {
            return res.status(400).json({ error: 'Username and PIN required' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }

        if (!/^\d{4}$/.test(pin)) {
            return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
        }

        const usernameLC = username.toLowerCase();

        if (action === 'register') {
            console.log('Auth: registering...');
            // Check if exists
            const existing = await db.execute({
                sql: 'SELECT id FROM users WHERE username = ?',
                args: [usernameLC]
            });
            if (existing.rows.length > 0) {
                return res.status(400).json({ error: 'Username already taken' });
            }

            const id = generateId();
            const pinHash = await bcrypt.hash(pin, 10);
            const createdAt = new Date().toISOString();

            await db.execute({
                sql: 'INSERT INTO users (id, username, pin_hash, created_at) VALUES (?, ?, ?, ?)',
                args: [id, usernameLC, pinHash, createdAt]
            });

            const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '30d' });
            console.log('Auth: register success');
            return res.status(201).json({ token, userId: id });
        } else {
            console.log('Auth: logging in...');
            // Login
            const result = await db.execute({
                sql: 'SELECT id, pin_hash FROM users WHERE username = ?',
                args: [usernameLC]
            });

            if (result.rows.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const user = result.rows[0];
            const valid = await bcrypt.compare(pin, user.pin_hash);

            if (!valid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
            console.log('Auth: login success');
            return res.json({ token, userId: user.id });
        }
    } catch (error) {
        console.error('Auth error:', error.message);
        console.error('Auth error stack:', error.stack);
        return res.status(500).json({ error: 'Server error: ' + error.message });
    }
};
