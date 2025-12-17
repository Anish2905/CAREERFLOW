const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { initDatabase, getDb, saveDatabase } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// FIX-002: JWT_SECRET must be set in production; warn in development
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    if (process.env.NODE_ENV === 'production') {
        console.error('FATAL: JWT_SECRET environment variable is required in production');
        process.exit(1);
    } else {
        console.warn('WARNING: JWT_SECRET not set. Using insecure default for development only.');
    }
}
const jwtSecret = JWT_SECRET || 'dev-only-insecure-secret-do-not-use-in-prod';

// Middleware - explicit CORS for Railway/Render
app.use(cors({
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.options('*', cors()); // Handle preflight for all routes
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ===== Auth Middleware =====
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.userId = decoded.userId;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// ===== UUID Generator =====
function generateId() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

// ===== FIX-003: Simple Rate Limiting for Auth Endpoints =====
const authAttempts = new Map(); // IP -> { count, resetTime }
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_ATTEMPTS = 5;

function rateLimitAuth(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();

    let record = authAttempts.get(ip);

    // Reset if window expired
    if (!record || now > record.resetTime) {
        record = { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };
        authAttempts.set(ip, record);
    }

    record.count++;

    if (record.count > RATE_LIMIT_MAX_ATTEMPTS) {
        const retryAfter = Math.ceil((record.resetTime - now) / 1000);
        res.setHeader('Retry-After', retryAfter);
        return res.status(429).json({
            error: 'Too many attempts. Please try again later.',
            retryAfter
        });
    }

    next();
}

// Clean up old entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of authAttempts.entries()) {
        if (now > record.resetTime) {
            authAttempts.delete(ip);
        }
    }
}, 5 * 60 * 1000);

// ===== Auth Routes =====

// Register
app.post('/api/register', rateLimitAuth, async (req, res) => {
    try {
        const db = getDb();
        if (!db) {
            console.error('Database not initialized');
            return res.status(503).json({ error: 'Database not ready, please try again' });
        }
        const { username, pin } = req.body;

        if (!username || !pin) {
            return res.status(400).json({ error: 'Username and PIN required' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }

        if (!/^\d{4}$/.test(pin)) {
            return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
        }

        // Check if user exists
        const existing = db.exec('SELECT id FROM users WHERE username = ?', [username.toLowerCase()]);
        if (existing.length > 0 && existing[0].values.length > 0) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        const id = generateId();
        const pinHash = await bcrypt.hash(pin, 10);
        const createdAt = new Date().toISOString();

        db.run(
            'INSERT INTO users (id, username, pin_hash, created_at) VALUES (?, ?, ?, ?)',
            [id, username.toLowerCase(), pinHash, createdAt]
        );
        saveDatabase();

        const token = jwt.sign({ userId: id }, jwtSecret, { expiresIn: '30d' });
        res.status(201).json({ token, userId: id });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed: ' + (error.message || 'Unknown error') });
    }
});

// Login
app.post('/api/login', rateLimitAuth, async (req, res) => {
    try {
        const db = getDb();
        if (!db) {
            console.error('Database not initialized');
            return res.status(503).json({ error: 'Database not ready, please try again' });
        }
        const { username, pin } = req.body;

        if (!username || !pin) {
            return res.status(400).json({ error: 'Username and PIN required' });
        }

        const result = db.exec('SELECT id, pin_hash FROM users WHERE username = ?', [username.toLowerCase()]);
        if (result.length === 0 || result[0].values.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const [userId, pinHash] = result[0].values[0];
        const valid = await bcrypt.compare(pin, pinHash);

        if (!valid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId }, jwtSecret, { expiresIn: '30d' });
        res.json({ token, userId });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed: ' + (error.message || 'Unknown error') });
    }
});

// ===== Protected Application Routes =====

// GET all applications for user
app.get('/api/applications', authMiddleware, (req, res) => {
    try {
        const db = getDb();
        const results = db.exec(
            'SELECT * FROM applications WHERE user_id = ? ORDER BY created_at DESC',
            [req.userId]
        );

        if (results.length === 0) {
            return res.json([]);
        }

        const columns = results[0].columns;
        const rows = results[0].values;

        const applications = rows.map(row => {
            const obj = {};
            columns.forEach((col, i) => {
                const key = col.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
                obj[key] = row[i];
            });
            return obj;
        });

        res.json(applications);
    } catch (error) {
        console.error('GET error:', error);
        res.status(500).json({ error: 'Failed to fetch applications' });
    }
});

// POST new application
app.post('/api/applications', authMiddleware, (req, res) => {
    try {
        const db = getDb();
        const { id, company, position, location, status, appliedDate, deadline, tags, url, notes, resumeUrl, createdAt, updatedAt } = req.body;

        db.run(`
      INSERT INTO applications (id, user_id, company, position, location, status, applied_date, deadline, tags, url, notes, resume_url, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [id, req.userId, company, position, location || null, status || 'wishlist', appliedDate || null, deadline || null, tags ? JSON.stringify(tags) : null, url || null, notes || null, resumeUrl || null, createdAt, updatedAt]);

        saveDatabase();
        res.status(201).json({ success: true, id });
    } catch (error) {
        console.error('POST error:', error);
        res.status(500).json({ error: 'Failed to create application' });
    }
});

// PUT update application
app.put('/api/applications/:id', authMiddleware, (req, res) => {
    try {
        const db = getDb();
        const { id } = req.params;
        const { company, position, location, status, appliedDate, deadline, tags, url, notes, resumeUrl, updatedAt } = req.body;

        // Verify ownership
        const check = db.exec('SELECT id FROM applications WHERE id = ? AND user_id = ?', [id, req.userId]);
        if (check.length === 0 || check[0].values.length === 0) {
            return res.status(404).json({ error: 'Application not found' });
        }

        db.run(`
      UPDATE applications 
      SET company = ?, position = ?, location = ?, status = ?, applied_date = ?, deadline = ?, tags = ?, url = ?, notes = ?, resume_url = ?, updated_at = ?
      WHERE id = ? AND user_id = ?
    `, [company, position, location || null, status, appliedDate || null, deadline || null, tags ? JSON.stringify(tags) : null, url || null, notes || null, resumeUrl || null, updatedAt, id, req.userId]);

        saveDatabase();
        res.json({ success: true });
    } catch (error) {
        console.error('PUT error:', error);
        res.status(500).json({ error: 'Failed to update application' });
    }
});

// DELETE application
app.delete('/api/applications/:id', authMiddleware, (req, res) => {
    try {
        const db = getDb();
        const { id } = req.params;

        // Verify ownership
        const check = db.exec('SELECT id FROM applications WHERE id = ? AND user_id = ?', [id, req.userId]);
        if (check.length === 0 || check[0].values.length === 0) {
            return res.status(404).json({ error: 'Application not found' });
        }

        db.run('DELETE FROM applications WHERE id = ? AND user_id = ?', [id, req.userId]);
        saveDatabase();

        res.json({ success: true });
    } catch (error) {
        console.error('DELETE error:', error);
        res.status(500).json({ error: 'Failed to delete application' });
    }
});

// Restore application (for undo functionality)
app.post('/api/applications/restore', authMiddleware, (req, res) => {
    try {
        const db = getDb();
        const { id, company, position, status, appliedDate, url, notes, createdAt, updatedAt } = req.body;

        db.run(`
      INSERT INTO applications (id, user_id, company, position, status, applied_date, url, notes, resume_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [id, req.userId, company, position, status, appliedDate || null, url || null, notes || null, req.body.resumeId || null, createdAt, updatedAt]);

        saveDatabase();
        res.status(201).json({ success: true });
    } catch (error) {
        console.error('RESTORE error:', error);
        res.status(500).json({ error: 'Failed to restore application' });
    }
});

// ===== Resume Sync (Full Implementation) =====
// Note: resumes table is now created in database.js initDatabase() - FIX-001

app.get('/api/resume-sync', authMiddleware, (req, res) => {
    try {
        const db = getDb();
        const { id } = req.query;

        // 1. Single Fetch (Full Data)
        if (id) {
            const result = db.exec('SELECT * FROM resumes WHERE id = ? AND user_id = ? AND deleted_at IS NULL', [id, req.userId]);
            if (result.length === 0 || result[0].values.length === 0) {
                return res.status(404).json({ error: 'Resume not found' });
            }
            const columns = result[0].columns;
            const row = result[0].values[0];
            const resume = {};
            columns.forEach((col, i) => {
                const key = col.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
                resume[key] = row[i];
            });
            return res.json({ resume });
        }

        // 2. List Fetch (Metadata Only)
        const result = db.exec(`
            SELECT id, name, file_name, file_type, created_at, updated_at 
            FROM resumes WHERE user_id = ? AND deleted_at IS NULL 
            ORDER BY created_at DESC
        `, [req.userId]);

        if (result.length === 0) {
            return res.json({ resumes: [] });
        }

        const columns = result[0].columns;
        const resumes = result[0].values.map(row => {
            const obj = {};
            columns.forEach((col, i) => {
                const key = col.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
                obj[key] = row[i];
            });
            return obj;
        });
        res.json({ resumes });

    } catch (e) {
        console.error('Resume GET error:', e);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/resume-sync', authMiddleware, (req, res) => {
    try {
        const db = getDb();
        const { action, resume } = req.body;

        if (action === 'upload') {
            db.run(`
                INSERT OR REPLACE INTO resumes (id, user_id, name, file_name, file_data, file_type, created_at, updated_at, deleted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            `, [resume.id, req.userId, resume.name, resume.fileName, resume.fileData, resume.fileType, resume.createdAt, resume.updatedAt]);
            saveDatabase();
            return res.json({ success: true });
        }

        if (action === 'delete') {
            db.run('UPDATE resumes SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ?',
                [new Date().toISOString(), new Date().toISOString(), resume.id, req.userId]);
            saveDatabase();
            return res.json({ success: true });
        }

        res.status(400).json({ error: 'Invalid action' });
    } catch (e) {
        console.error('Resume POST error:', e);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== App Sync (local dev - just acknowledge) =====
app.get('/api/sync', authMiddleware, (req, res) => {
    // Local dev: apps are stored via CRUD, minimal sync needed
    res.json({ applications: [], serverTime: new Date().toISOString() });
});

app.post('/api/sync', authMiddleware, (req, res) => {
    // Local dev: acknowledge changes
    res.json({ applications: [], serverTime: new Date().toISOString() });
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Initialize database and start server
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
