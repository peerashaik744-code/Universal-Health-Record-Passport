// server/routes/auth.js
const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("../db");
const { signToken } = require("../auth");
const { logAction } = require("../audit");

const router = express.Router();

// POST /api/auth/register
router.post("/register", async (req, res) => {
  const { name, email, password, role, facility } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: "name, email, password, role are required" });
  }
  if (!["patient", "doctor", "admin"].includes(role)) {
    return res.status(400).json({ error: "role must be patient, doctor, or admin" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) return res.status(409).json({ error: "email already registered" });

  const hash = await bcrypt.hash(password, 12);

  // Doctors/admins start unverified until an admin approves them, so a
  // random signup can't immediately go scan and read patient data.
  const verified = role === "patient" ? 1 : 0;

  const info = db
    .prepare(
      `INSERT INTO users (name, email, password_hash, role, facility, verified)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(name, email, hash, role, facility || null, verified);

  if (role === "patient") {
    db.prepare(
      `INSERT INTO health_profiles (patient_id, blood_type, allergies, conditions, medications, emergency_contact)
       VALUES (?, '', '', '', '', '')`
    ).run(info.lastInsertRowid);
  }

  logAction({
    actorId: info.lastInsertRowid,
    actorRole: role,
    action: "USER_REGISTERED",
    patientId: role === "patient" ? info.lastInsertRowid : null,
    metadata: { email },
  });

  const user = { id: info.lastInsertRowid, role, name, email };
  res.status(201).json({
    token: signToken(user),
    user,
    note:
      role === "patient"
        ? undefined
        : "Account created but pending admin verification before you can scan patient QR codes.",
  });
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  logAction({
    actorId: user.id,
    actorRole: user.role,
    action: "LOGIN",
    patientId: user.role === "patient" ? user.id : null,
  });

  res.json({
    token: signToken(user),
    user: {
      id: user.id,
      role: user.role,
      name: user.name,
      email: user.email,
      verified: !!user.verified,
    },
  });
});

module.exports = router;
