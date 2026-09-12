// server/audit.js
// Tamper-evident audit trail using a simple append-only hash chain.
// This is the "blockchain/tamper-evident audit" requirement implemented
// pragmatically for a hackathon: no external chain/network needed, but the
// data structure and verification method are the same idea a permissioned
// blockchain gives you -- any retroactive edit breaks the hash chain.

const crypto = require("crypto");
const db = require("./db");

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function getLastHash() {
  const row = db
    .prepare("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
    .get();
  return row ? row.hash : "GENESIS";
}

/**
 * Append a new audit entry. Returns the created row.
 */
function logAction({ actorId, actorRole, action, patientId, metadata }) {
  const prevHash = getLastHash();
  const createdAt = new Date().toISOString();
  const payload = JSON.stringify({
    actorId,
    actorRole,
    action,
    patientId,
    metadata,
    createdAt,
    prevHash,
  });
  const hash = sha256(payload);

  const stmt = db.prepare(`
    INSERT INTO audit_log (actor_id, actor_role, action, patient_id, metadata, prev_hash, hash, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    actorId || null,
    actorRole || null,
    action,
    patientId || null,
    metadata ? JSON.stringify(metadata) : null,
    prevHash,
    hash,
    createdAt
  );

  return { hash, prevHash, createdAt };
}

/**
 * Recompute the chain from scratch and confirm every hash matches.
 * Returns { valid: boolean, brokenAtId?: number }
 */
function verifyChain() {
  const rows = db.prepare("SELECT * FROM audit_log ORDER BY id ASC").all();
  let expectedPrev = "GENESIS";

  for (const row of rows) {
    if (row.prev_hash !== expectedPrev) {
      return { valid: false, brokenAtId: row.id, reason: "prev_hash mismatch" };
    }
    const payload = JSON.stringify({
      actorId: row.actor_id,
      actorRole: row.actor_role,
      action: row.action,
      patientId: row.patient_id,
      metadata: row.metadata ? JSON.parse(row.metadata) : null,
      createdAt: row.created_at,
      prevHash: row.prev_hash,
    });
    const recomputed = sha256(payload);
    if (recomputed !== row.hash) {
      return { valid: false, brokenAtId: row.id, reason: "hash mismatch" };
    }
    expectedPrev = row.hash;
  }

  return { valid: true, blocks: rows.length };
}

function historyForPatient(patientId) {
  return db
    .prepare("SELECT * FROM audit_log WHERE patient_id = ? ORDER BY id DESC")
    .all(patientId);
}

module.exports = { logAction, verifyChain, historyForPatient, sha256 };
