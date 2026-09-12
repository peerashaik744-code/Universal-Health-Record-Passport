// server/db.js
// SQLite setup + schema. Using better-sqlite3 for simplicity in a hackathon
// context -- swap for Postgres/MySQL for real multi-region deployment.

const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const DB_PATH = process.env.DB_PATH || "./data/passport.db";
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('patient','doctor','admin')),
  facility      TEXT,               -- hospital/clinic name, for doctors
  verified      INTEGER DEFAULT 0,  -- doctors/facilities pending admin verification
  created_at    TEXT DEFAULT (datetime('now'))
);

-- One passport / emergency card per patient
CREATE TABLE IF NOT EXISTS health_profiles (
  patient_id        INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  blood_type        TEXT,
  allergies         TEXT,   -- comma separated, kept simple for MVP
  conditions        TEXT,
  medications       TEXT,
  emergency_contact TEXT,
  updated_at        TEXT DEFAULT (datetime('now'))
);

-- Append-only medical timeline (visits, diagnoses, prescriptions, vaccines, labs)
CREATE TABLE IF NOT EXISTS medical_records (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  doctor_id   INTEGER REFERENCES users(id),
  facility    TEXT,
  record_type TEXT NOT NULL CHECK (record_type IN
                ('visit','diagnosis','prescription','vaccination','lab_report','note')),
  summary     TEXT NOT NULL,
  details     TEXT,
  record_hash TEXT NOT NULL,   -- sha256 of the entry, for tamper checks
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Patient consent grants: which doctor/facility may read the full record
CREATE TABLE IF NOT EXISTS consents (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  doctor_id   INTEGER REFERENCES users(id),
  facility    TEXT,
  scope       TEXT NOT NULL DEFAULT 'full' CHECK (scope IN ('full','emergency_only')),
  granted_at  TEXT DEFAULT (datetime('now')),
  expires_at  TEXT,
  revoked     INTEGER DEFAULT 0
);

-- Opaque QR scan tokens. The QR code itself only encodes a URL like
-- /scan/<token> -- never raw medical data, per the security requirement.
CREATE TABLE IF NOT EXISTS scan_tokens (
  token       TEXT PRIMARY KEY,
  patient_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mode        TEXT NOT NULL CHECK (mode IN ('standard','emergency')),
  expires_at  TEXT NOT NULL,
  used        INTEGER DEFAULT 0,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Tamper-evident, hash-chained audit log. Every sensitive action appends a
-- block whose hash depends on the previous block's hash (append-only ledger
-- pattern) so any later edit/deletion breaks the chain and is detectable.
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id    INTEGER,
  actor_role  TEXT,
  action      TEXT NOT NULL,
  patient_id  INTEGER,
  metadata    TEXT,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL,
  created_at  TEXT DEFAULT (datetime('now'))
);
`);

module.exports = db;
