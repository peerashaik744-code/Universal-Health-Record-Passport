// server/routes/patients.js
const express = require("express");
const crypto = require("crypto");
const db = require("../db");
const { requireAuth, requireRole } = require("../auth");
const { logAction } = require("../audit");

const router = express.Router();

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function hasActiveConsent(patientId, doctorId) {
  const row = db
    .prepare(
      `SELECT * FROM consents
       WHERE patient_id = ? AND doctor_id = ? AND scope = 'full' AND revoked = 0
         AND (expires_at IS NULL OR expires_at > datetime('now'))
       ORDER BY id DESC LIMIT 1`
    )
    .get(patientId, doctorId);
  return !!row;
}

// ---- Patient self-service ----------------------------------------------

// GET /api/patients/me  -- full own profile + timeline
router.get("/me", requireAuth, requireRole("patient"), (req, res) => {
  const profile = db
    .prepare("SELECT * FROM health_profiles WHERE patient_id = ?")
    .get(req.user.id);
  const records = db
    .prepare("SELECT * FROM medical_records WHERE patient_id = ? ORDER BY created_at DESC")
    .all(req.user.id);
  res.json({ profile, records });
});

// PUT /api/patients/me/profile -- update emergency-card fields
router.put("/me/profile", requireAuth, requireRole("patient"), (req, res) => {
  const { blood_type, allergies, conditions, medications, emergency_contact } = req.body;

  db.prepare(
    `UPDATE health_profiles
     SET blood_type = ?, allergies = ?, conditions = ?, medications = ?, emergency_contact = ?,
         updated_at = datetime('now')
     WHERE patient_id = ?`
  ).run(
    blood_type || "",
    allergies || "",
    conditions || "",
    medications || "",
    emergency_contact || "",
    req.user.id
  );

  logAction({
    actorId: req.user.id,
    actorRole: "patient",
    action: "PROFILE_UPDATED",
    patientId: req.user.id,
  });

  res.json({ ok: true });
});

// GET /api/patients/me/consents
router.get("/me/consents", requireAuth, requireRole("patient"), (req, res) => {
  const rows = db
    .prepare(
      `SELECT c.*, u.name as doctor_name, u.email as doctor_email, u.facility as doctor_facility
       FROM consents c LEFT JOIN users u ON u.id = c.doctor_id
       WHERE c.patient_id = ? ORDER BY c.id DESC`
    )
    .all(req.user.id);
  res.json(rows);
});

// POST /api/patients/me/consents -- grant a doctor (by email) access
router.post("/me/consents", requireAuth, requireRole("patient"), (req, res) => {
  const { doctor_email, expires_in_days } = req.body;
  if (!doctor_email) return res.status(400).json({ error: "doctor_email is required" });

  const doctor = db
    .prepare("SELECT * FROM users WHERE email = ? AND role = 'doctor'")
    .get(doctor_email);
  if (!doctor) return res.status(404).json({ error: "no doctor found with that email" });
  if (!doctor.verified) {
    return res.status(403).json({ error: "this doctor account is not yet admin-verified" });
  }

  const expiresAt = expires_in_days
    ? new Date(Date.now() + expires_in_days * 86400000).toISOString()
    : null;

  const info = db
    .prepare(
      `INSERT INTO consents (patient_id, doctor_id, facility, scope, expires_at)
       VALUES (?, ?, ?, 'full', ?)`
    )
    .run(req.user.id, doctor.id, doctor.facility, expiresAt);

  logAction({
    actorId: req.user.id,
    actorRole: "patient",
    action: "CONSENT_GRANTED",
    patientId: req.user.id,
    metadata: { doctorId: doctor.id, doctorEmail: doctor.email, expiresAt },
  });

  res.status(201).json({ id: info.lastInsertRowid, doctor: { id: doctor.id, name: doctor.name } });
});

// POST /api/patients/me/consents/:id/revoke
router.post("/me/consents/:id/revoke", requireAuth, requireRole("patient"), (req, res) => {
  const consent = db
    .prepare("SELECT * FROM consents WHERE id = ? AND patient_id = ?")
    .get(req.params.id, req.user.id);
  if (!consent) return res.status(404).json({ error: "consent not found" });

  db.prepare("UPDATE consents SET revoked = 1 WHERE id = ?").run(consent.id);

  logAction({
    actorId: req.user.id,
    actorRole: "patient",
    action: "CONSENT_REVOKED",
    patientId: req.user.id,
    metadata: { consentId: consent.id, doctorId: consent.doctor_id },
  });

  res.json({ ok: true });
});

// GET /api/patients/me/audit -- "who accessed my record" view
router.get("/me/audit", requireAuth, requireRole("patient"), (req, res) => {
  const rows = db
    .prepare(
      `SELECT a.*, u.name as actor_name FROM audit_log a
       LEFT JOIN users u ON u.id = a.actor_id
       WHERE a.patient_id = ? ORDER BY a.id DESC LIMIT 200`
    )
    .all(req.user.id);
  res.json(rows);
});

// ---- Doctor access to a specific patient (requires active consent) ----

// GET /api/patients/:patientId  -- doctor reads full record (consent required)
router.get("/:patientId", requireAuth, requireRole("doctor", "admin"), (req, res) => {
  const patientId = Number(req.params.patientId);

  if (req.user.role === "doctor") {
    const doc = db.prepare("SELECT verified FROM users WHERE id = ?").get(req.user.id);
    if (!doc || !doc.verified) {
      return res.status(403).json({ error: "Your doctor account is pending admin verification." });
    }
    if (!hasActiveConsent(patientId, req.user.id)) {
      return res.status(403).json({ error: "no active patient consent for this doctor" });
    }
  }

  const profile = db.prepare("SELECT * FROM health_profiles WHERE patient_id = ?").get(patientId);
  const records = db
    .prepare("SELECT * FROM medical_records WHERE patient_id = ? ORDER BY created_at DESC")
    .all(patientId);

  if (!profile) return res.status(404).json({ error: "patient not found" });

  logAction({
    actorId: req.user.id,
    actorRole: req.user.role,
    action: "FULL_RECORD_VIEWED",
    patientId,
  });

  res.json({ profile, records });
});

// POST /api/patients/:patientId/records -- doctor appends a timeline entry
router.post("/:patientId/records", requireAuth, requireRole("doctor"), (req, res) => {
  const patientId = Number(req.params.patientId);
  const { record_type, summary, details } = req.body;

  const doc = db.prepare("SELECT verified FROM users WHERE id = ?").get(req.user.id);
  if (!doc || !doc.verified) {
    return res.status(403).json({ error: "Your doctor account is pending admin verification." });
  }

  if (!hasActiveConsent(patientId, req.user.id)) {
    return res.status(403).json({ error: "no active patient consent for this doctor" });
  }
  const validTypes = ["visit", "diagnosis", "prescription", "vaccination", "lab_report", "note"];
  if (!validTypes.includes(record_type)) {
    return res.status(400).json({ error: `record_type must be one of ${validTypes.join(", ")}` });
  }
  if (!summary) return res.status(400).json({ error: "summary is required" });

  const doctor = db.prepare("SELECT facility FROM users WHERE id = ?").get(req.user.id);
  const hash = sha256(`${patientId}|${req.user.id}|${record_type}|${summary}|${Date.now()}`);

  const info = db
    .prepare(
      `INSERT INTO medical_records (patient_id, doctor_id, facility, record_type, summary, details, record_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(patientId, req.user.id, doctor?.facility || null, record_type, summary, details || null, hash);

  logAction({
    actorId: req.user.id,
    actorRole: "doctor",
    action: "RECORD_ADDED",
    patientId,
    metadata: { recordId: info.lastInsertRowid, record_type },
  });

  res.status(201).json({ id: info.lastInsertRowid, record_hash: hash });
});

module.exports = router;
