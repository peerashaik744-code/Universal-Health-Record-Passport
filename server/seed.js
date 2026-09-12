// server/seed.js
// Optional: populate demo accounts so judges can log in immediately.
// Run with: npm run seed

require("dotenv").config();
const bcrypt = require("bcryptjs");
const db = require("./db");
const { logAction } = require("./audit");

async function upsertUser({ name, email, password, role, facility, verified }) {
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) return existing.id;

  const hash = await bcrypt.hash(password, 12);
  const info = db
    .prepare(
      `INSERT INTO users (name, email, password_hash, role, facility, verified)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(name, email, hash, role, facility || null, verified ? 1 : 0);
  return info.lastInsertRowid;
}

async function main() {
  const adminId = await upsertUser({
    name: "Admin",
    email: "admin@demo.org",
    password: "admin12345",
    role: "admin",
    verified: true,
  });

  const doctorId = await upsertUser({
    name: "Dr. Amara Obi",
    email: "doctor@demo.org",
    password: "doctor12345",
    role: "doctor",
    facility: "Nairobi General Clinic",
    verified: true,
  });

  const patientId = await upsertUser({
    name: "Jane Doe",
    email: "patient@demo.org",
    password: "patient12345",
    role: "patient",
    verified: true,
  });

  const profileExists = db
    .prepare("SELECT patient_id FROM health_profiles WHERE patient_id = ?")
    .get(patientId);
  if (!profileExists) {
    db.prepare(
      `INSERT INTO health_profiles (patient_id, blood_type, allergies, conditions, medications, emergency_contact)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(
      patientId,
      "O+",
      "Penicillin",
      "Type 1 Diabetes",
      "Insulin (rapid-acting, 3x daily)",
      "+254 700 000 000 (sister, Amina)"
    );
    logAction({ actorId: patientId, actorRole: "patient", action: "PROFILE_UPDATED", patientId });
  }

  console.log("Seed complete. Demo accounts:");
  console.log("  admin@demo.org   / admin12345");
  console.log("  doctor@demo.org  / doctor12345  (Nairobi General Clinic, pre-verified)");
  console.log("  patient@demo.org / patient12345 (Jane Doe, O+, penicillin allergy)");
  console.log("\nNext: log in as the patient, grant consent to doctor@demo.org, then log in");
  console.log("as the doctor and scan/enter the generated QR token.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
