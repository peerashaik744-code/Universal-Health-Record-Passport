// server/routes/admin.js
const express = require("express");
const db = require("../db");
const { requireAuth, requireRole } = require("../auth");
const { verifyChain, logAction } = require("../audit");

const router = express.Router();
router.use(requireAuth, requireRole("admin"));

// GET /api/admin/users -- list everyone, e.g. to find unverified doctors
router.get("/users", (req, res) => {
  const rows = db
    .prepare("SELECT id, name, email, role, facility, verified, created_at FROM users ORDER BY id DESC")
    .all();
  res.json(rows);
});

// POST /api/admin/users/:id/verify -- approve a doctor/facility account
router.post("/users/:id/verify", (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "user not found" });

  db.prepare("UPDATE users SET verified = 1 WHERE id = ?").run(user.id);

  logAction({
    actorId: req.user.id,
    actorRole: "admin",
    action: "PROVIDER_VERIFIED",
    metadata: { userId: user.id, email: user.email },
  });

  res.json({ ok: true });
});

// GET /api/admin/audit -- full system audit trail
router.get("/audit", (req, res) => {
  const rows = db
    .prepare(
      `SELECT a.*, u.name as actor_name, p.name as patient_name
       FROM audit_log a
       LEFT JOIN users u ON u.id = a.actor_id
       LEFT JOIN users p ON p.id = a.patient_id
       ORDER BY a.id DESC LIMIT 500`
    )
    .all();
  res.json(rows);
});

// GET /api/admin/audit/verify -- recompute the hash chain and confirm integrity
router.get("/audit/verify", (req, res) => {
  res.json(verifyChain());
});

module.exports = router;
