// server/routes/qr.js
//
// IMPORTANT SECURITY REQUIREMENT (per spec): the QR code never contains raw
// medical data, passwords, or long-lived tokens. It only encodes a URL that
// points at an opaque, short-lived, single-purpose token id. All real data
// is fetched server-side after authentication + (for standard mode) an
// active consent check.

const express = require("express");
const crypto = require("crypto");
const QRCode = require("qrcode");
const db = require("../db");
const { requireAuth, requireRole } = require("../auth");
const { logAction } = require("../audit");

const router = express.Router();

const QR_TTL_MIN = Number(process.env.QR_TOKEN_TTL_MINUTES || 15);
const EMERGENCY_TTL_MIN = Number(process.env.EMERGENCY_TOKEN_TTL_MINUTES || 60);
const BASE_URL = process.env.PUBLIC_BASE_URL || "http://localhost:4000";

function makeToken() {
  return crypto.randomBytes(24).toString("hex"); // opaque, unguessable
}

// POST /api/qr/generate  { mode: 'standard' | 'emergency' }
router.post("/generate", requireAuth, requireRole("patient"), async (req, res) => {
  const mode = req.body.mode === "emergency" ? "emergency" : "standard";
  const ttlMinutes = mode === "emergency" ? EMERGENCY_TTL_MIN : QR_TTL_MIN;

  const token = makeToken();
  const expiresAt = new Date(Date.now() + ttlMinutes * 60000).toISOString();

  db.prepare(
    `INSERT INTO scan_tokens (token, patient_id, mode, expires_at) VALUES (?, ?, ?, ?)`
  ).run(token, req.user.id, mode, expiresAt);

  const scanUrl = `${BASE_URL}/scan/${token}`;
  const qrDataUrl = await QRCode.toDataURL(scanUrl, { margin: 1, width: 320 });

  logAction({
    actorId: req.user.id,
    actorRole: "patient",
    action: "QR_GENERATED",
    patientId: req.user.id,
    metadata: { mode, expiresAt },
  });

  res.json({ token, scanUrl, qrDataUrl, mode, expiresAt });
});

// GET /api/qr/scan/:token  -- a doctor/admin scans and this resolves it.
// Standard mode requires an active consent grant; emergency mode returns
// only the critical-care fields regardless of consent (but is fully logged).
router.get("/scan/:token", requireAuth, requireRole("doctor", "admin"), (req, res) => {
  if (req.user.role === "doctor") {
    const doc = db.prepare("SELECT verified FROM users WHERE id = ?").get(req.user.id);
    if (!doc || !doc.verified) {
      return res.status(403).json({ error: "Your doctor account is pending admin verification before you can scan QR codes." });
    }
  }

  const row = db.prepare("SELECT * FROM scan_tokens WHERE token = ?").get(req.params.token);
  if (!row) return res.status(404).json({ error: "invalid or unknown token" });
  if (new Date(row.expires_at) < new Date()) {
    return res.status(410).json({ error: "this QR code has expired -- ask the patient to regenerate it" });
  }

  const profile = db
    .prepare("SELECT * FROM health_profiles WHERE patient_id = ?")
    .get(row.patient_id);
  const patient = db
    .prepare("SELECT id, name FROM users WHERE id = ?")
    .get(row.patient_id);

  if (!patient || !profile) {
    return res.status(404).json({ error: "patient profile not found" });
  }

  if (row.mode === "emergency") {
    logAction({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "EMERGENCY_ACCESS",
      patientId: row.patient_id,
      metadata: { token: row.token },
    });
    return res.json({
      mode: "emergency",
      patient: { name: patient.name },
      emergencyCard: {
        blood_type: profile.blood_type,
        allergies: profile.allergies,
        conditions: profile.conditions,
        medications: profile.medications,
        emergency_contact: profile.emergency_contact,
      },
    });
  }

  // standard mode -> requires consent, unless the doctor is the one who
  // already has it; otherwise tell them to request access from the patient.
  const consent = db
    .prepare(
      `SELECT * FROM consents WHERE patient_id = ? AND doctor_id = ? AND scope = 'full'
       AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now'))
       ORDER BY id DESC LIMIT 1`
    )
    .get(row.patient_id, req.user.id);

  if (!consent && req.user.role !== "admin") {
    logAction({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ACCESS_DENIED_NO_CONSENT",
      patientId: row.patient_id,
      metadata: { token: row.token },
    });
    return res.status(403).json({
      error: "no active consent on file for this doctor",
      patient: { id: patient.id, name: patient.name },
      hint: "Ask the patient to grant you access from their consent management screen using your registered email.",
    });
  }

  const records = db
    .prepare("SELECT * FROM medical_records WHERE patient_id = ? ORDER BY created_at DESC")
    .all(row.patient_id);

  logAction({
    actorId: req.user.id,
    actorRole: req.user.role,
    action: "QR_STANDARD_ACCESS",
    patientId: row.patient_id,
    metadata: { token: row.token },
  });

  res.json({ mode: "standard", patient, profile, records });
});

module.exports = router;
