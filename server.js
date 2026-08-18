const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ¦¦¦ Config ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "CHANGE_THIS_SECRET";
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || "./szaby_licenses.db";

// ¦¦¦ Database Setup ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT UNIQUE NOT NULL,
    label       TEXT,
    duration    TEXT NOT NULL,
    activated   INTEGER DEFAULT 0,
    hwid        TEXT,
    activated_at TEXT,
    expires_at  TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    banned      INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS banned_hwids (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid    TEXT UNIQUE NOT NULL,
    reason  TEXT,
    banned_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS logs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    type     TEXT,
    key      TEXT,
    hwid     TEXT,
    ip       TEXT,
    result   TEXT,
    ts       TEXT DEFAULT (datetime('now'))
  );
`);

// ¦¦¦ Helpers ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦
function generateKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const rand = (n) => Array.from({ length: n }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `SZABY-${rand(4)}-${rand(4)}-${rand(4)}`;
}

function calcExpiry(duration) {
  const now = new Date();
  if (duration === "30d")  now.setDate(now.getDate() + 30);
  else if (duration === "365d") now.setDate(now.getDate() + 365);
  else if (duration === "lifetime") return "9999-12-31T23:59:59Z";
  else now.setDate(now.getDate() + 30); // default
  return now.toISOString();
}

function adminGuard(req, res, next) {
  const token = req.headers["x-admin-token"] || req.query.admintoken;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: "Forbidden" });
  next();
}

function log(type, key, hwid, ip, result) {
  try {
    db.prepare("INSERT INTO logs (type, key, hwid, ip, result) VALUES (?,?,?,?,?)").run(type, key, hwid, ip, result);
  } catch (_) {}
}

// ¦¦¦ PUBLIC API ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦

// Validate key + HWID
app.get("/api/validate", (req, res) => {
  const { key, hwid } = req.query;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  if (!key || !hwid) return res.json({ status: "INVALID", reason: "Missing params" });

  // Check HWID ban first
  const hwidBan = db.prepare("SELECT 1 FROM banned_hwids WHERE hwid = ?").get(hwid);
  if (hwidBan) {
    log("validate", key, hwid, ip, "BANNED");
    return res.json({ status: "BANNED", reason: "This device has been permanently banned." });
  }

  const row = db.prepare("SELECT * FROM keys WHERE key = ?").get(key);

  if (!row) {
    log("validate", key, hwid, ip, "INVALID");
    return res.json({ status: "INVALID", reason: "Key not found." });
  }

  if (row.banned) {
    log("validate", key, hwid, ip, "BANNED");
    return res.json({ status: "BANNED", reason: "This key has been revoked." });
  }

  // First activation: bind HWID
  if (!row.activated) {
    const expiresAt = calcExpiry(row.duration);
    db.prepare("UPDATE keys SET activated=1, hwid=?, activated_at=datetime('now'), expires_at=? WHERE key=?")
      .run(hwid, expiresAt, key);
    log("validate", key, hwid, ip, "ACTIVATED");
    return res.json({ status: "VALID", expires_at: expiresAt, message: "Activated!" });
  }

  // Already activated - check HWID matches
  if (row.hwid !== hwid) {
    log("validate", key, hwid, ip, "HWID_MISMATCH");
    return res.json({ status: "INVALID", reason: "Key already activated on a different device." });
  }

  // Check expiry
  if (row.expires_at !== "9999-12-31T23:59:59Z" && new Date(row.expires_at) < new Date()) {
    log("validate", key, hwid, ip, "EXPIRED");
    return res.json({ status: "EXPIRED", reason: "License expired.", expired_at: row.expires_at });
  }

  log("validate", key, hwid, ip, "VALID");
  return res.json({ status: "VALID", expires_at: row.expires_at });
});

// Report bypass attempt - client calls this when it detects the server is being blocked
app.post("/api/report-bypass", (req, res) => {
  const { hwid, key } = req.body;
  if (!hwid) return res.sendStatus(400);
  try {
    db.prepare("INSERT OR IGNORE INTO banned_hwids (hwid, reason) VALUES (?, ?)").run(hwid, "Auto-ban: server bypass detected");
    if (key) db.prepare("UPDATE keys SET banned=1 WHERE key=?").run(key);
    log("bypass", key || "?", hwid, req.headers["x-forwarded-for"] || req.socket.remoteAddress, "AUTO_BANNED");
  } catch (_) {}
  return res.json({ status: "ok" });
});

// ¦¦¦ ADMIN API ¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦

// Generate key
app.post("/admin/keys/generate", adminGuard, (req, res) => {
  const { duration = "30d", label = "" } = req.body;
  let key;
  let tries = 0;
  do {
    key = generateKey();
    tries++;
  } while (db.prepare("SELECT 1 FROM keys WHERE key=?").get(key) && tries < 10);

  db.prepare("INSERT INTO keys (key, label, duration) VALUES (?, ?, ?)").run(key, label, duration);
  res.json({ key, duration, label });
});

// List all keys
app.get("/admin/keys", adminGuard, (req, res) => {
  const keys = db.prepare("SELECT * FROM keys ORDER BY created_at DESC").all();
  res.json(keys);
});

// Revoke key
app.post("/admin/keys/revoke", adminGuard, (req, res) => {
  const { key } = req.body;
  db.prepare("UPDATE keys SET banned=1 WHERE key=?").run(key);
  res.json({ status: "ok" });
});

// HWID Ban
app.post("/admin/ban", adminGuard, (req, res) => {
  const { hwid, reason = "Manual ban by admin" } = req.body;
  if (!hwid) return res.status(400).json({ error: "hwid required" });
  db.prepare("INSERT OR IGNORE INTO banned_hwids (hwid, reason) VALUES (?, ?)").run(hwid, reason);
  db.prepare("UPDATE keys SET banned=1 WHERE hwid=?").run(hwid);
  res.json({ status: "ok", hwid });
});

// HWID Unban
app.post("/admin/unban", adminGuard, (req, res) => {
  const { hwid } = req.body;
  db.prepare("DELETE FROM banned_hwids WHERE hwid=?").run(hwid);
  db.prepare("UPDATE keys SET banned=0 WHERE hwid=?").run(hwid);
  res.json({ status: "ok" });
});

// List banned HWIDs
app.get("/admin/banned", adminGuard, (req, res) => {
  const list = db.prepare("SELECT * FROM banned_hwids ORDER BY banned_at DESC").all();
  res.json(list);
});

// Recent logs
app.get("/admin/logs", adminGuard, (req, res) => {
  const rows = db.prepare("SELECT * FROM logs ORDER BY ts DESC LIMIT 200").all();
  res.json(rows);
});

// Admin dashboard HTML
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Root - redirect to admin
app.get('/', (req, res) => res.redirect('/admin'));

// Health check
app.get("/health", (req, res) => res.json({ status: "ok", ts: new Date().toISOString() }));

app.listen(PORT, () => console.log(`Szaby License Server running on port ${PORT}`));
