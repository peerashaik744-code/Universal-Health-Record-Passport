// server/index.js
require("dotenv").config();

const path = require("path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const authRoutes = require("./routes/auth");
const patientRoutes = require("./routes/patients");
const qrRoutes = require("./routes/qr");
const adminRoutes = require("./routes/admin");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(helmet({ contentSecurityPolicy: false })); // CSP relaxed for the simple demo frontend
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Basic global rate limit -- tighten per-route (esp. /auth) for production.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Stricter limiter for auth endpoints to slow down credential stuffing.
const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20 });
app.use("/api/auth", authLimiter, authRoutes);

app.use("/api/patients", patientRoutes);
app.use("/api/qr", qrRoutes);
app.use("/api/admin", adminRoutes);

app.get("/api/health", (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// Static frontend (plain HTML/CSS/JS -- no build step needed for the demo)
app.use(express.static(path.join(__dirname, "..", "public")));

// A scanned QR lands here: /scan/<token>. We just hand it to the doctor
// dashboard page, which reads the token from the URL and calls
// GET /api/qr/scan/:token once the doctor is logged in.
app.get("/scan/:token", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "doctor.html"));
});

app.use((req, res) => res.status(404).json({ error: "not found" }));

// Centralized error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "internal server error" });
});

app.listen(PORT, () => {
  console.log(`Universal Health Record Passport API running on http://localhost:${PORT}`);
});
