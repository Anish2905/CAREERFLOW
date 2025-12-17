const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const dbPath = path.join(__dirname, 'applications.db');
let db;

async function initDatabase() {
  const SQL = await initSqlJs();

  // Load existing database if it exists
  if (fs.existsSync(dbPath)) {
    const buffer = fs.readFileSync(dbPath);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  // Initialize schema - Users table (username + PIN)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pin_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  // Applications table with user_id
  db.run(`
    CREATE TABLE IF NOT EXISTS applications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      company TEXT NOT NULL,
      position TEXT NOT NULL,
      location TEXT,
      status TEXT NOT NULL DEFAULT 'wishlist',
      applied_date TEXT,
      url TEXT,
      notes TEXT,
      resume_url TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Migration: Add location column if it doesn't exist (for existing databases)
  try {
    db.run('ALTER TABLE applications ADD COLUMN location TEXT');
  } catch (e) {
    // Column already exists, ignore
  }

  // Migration: Add deadline column for application deadline tracking
  try {
    db.run('ALTER TABLE applications ADD COLUMN deadline TEXT');
  } catch (e) {
    // Column already exists, ignore
  }

  // Migration: Add tags column (stored as JSON array)
  try {
    db.run('ALTER TABLE applications ADD COLUMN tags TEXT');
  } catch (e) {
    // Column already exists, ignore
  }

  // Resumes table for cloud storage (FIX-001: moved from server.js)
  db.run(`
    CREATE TABLE IF NOT EXISTS resumes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_data TEXT NOT NULL,
      file_type TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      deleted_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  saveDatabase();
  return db;
}

function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(dbPath, buffer);
}

function getDb() {
  return db;
}

module.exports = { initDatabase, getDb, saveDatabase };
