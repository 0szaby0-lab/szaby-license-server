const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, x-admin-token");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.use(express.static(path.join(__dirname, "public")));

// ─── Config ─────────────────────────────────────────────────────────────────
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "CHANGE_THIS_SECRET";
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || "./szaby_licenses.db";

// ─── Database Setup ──────────────────────────────────────────────────────────
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key          TEXT UNIQUE NOT NULL,
    label        TEXT,
    duration     TEXT NOT NULL,
    activated    INTEGER DEFAULT 0,
    hwid         TEXT,
    activated_at TEXT,
    expires_at   TEXT,
    created_at   TEXT DEFAULT (datetime('now')),
    banned       INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS banned_hwids (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid      TEXT UNIQUE NOT NULL,
    reason    TEXT,
    banned_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS logs (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    type   TEXT,
    key    TEXT,
    hwid   TEXT,
    ip     TEXT,
    result TEXT,
    ts     TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS active_sessions (
    hwid         TEXT PRIMARY KEY,
    key          TEXT,
    label        TEXT,
    app_type     TEXT DEFAULT 'YouTube',
    video_id     TEXT,
    video_title  TEXT,
    channel_name TEXT,
    last_seen    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_hwid  TEXT DEFAULT 'ALL',
    title        TEXT,
    message      TEXT NOT NULL,
    type         TEXT DEFAULT 'toast',
    created_at   TEXT DEFAULT (datetime('now')),
    delivered_to TEXT DEFAULT '[]'
  );
`);

// ─── Helpers ─────────────────────────────────────────────────────────────────
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

// ─── PUBLIC API ───────────────────────────────────────────────────────────────

// Validate key + HWID
app.get("/api/validate", (req, res) => {
  const key = (req.query.key || "").trim().toUpperCase();
  const hwid = (req.query.hwid || "").trim();
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

// Client heartbeat: reports current playback and fetches pending admin messages
app.post("/api/heartbeat", (req, res) => {
  const { key, hwid, app_type = "YouTube", video_id = "", video_title = "", channel_name = "" } = req.body || {};
  const cleanKey = (key || "").trim().toUpperCase();
  const cleanHwid = (hwid || "").trim();

  if (!cleanKey || !cleanHwid) {
    return res.status(400).json({ status: "INVALID", reason: "Missing key or hwid" });
  }

  // Check HWID ban
  const hwidBan = db.prepare("SELECT 1 FROM banned_hwids WHERE hwid = ?").get(cleanHwid);
  if (hwidBan) {
    return res.json({ status: "BANNED", reason: "Device banned" });
  }

  // Check Key
  const row = db.prepare("SELECT * FROM keys WHERE key = ?").get(cleanKey);
  if (!row || row.banned) {
    return res.json({ status: "BANNED", reason: "Key invalid or revoked" });
  }

  if (row.hwid && row.hwid !== cleanHwid) {
    return res.json({ status: "INVALID", reason: "HWID mismatch" });
  }

  if (row.expires_at !== "9999-12-31T23:59:59Z" && new Date(row.expires_at) < new Date()) {
    return res.json({ status: "EXPIRED", reason: "License expired" });
  }

  // Upsert active session
  try {
    const existing = db.prepare("SELECT label FROM keys WHERE key = ?").get(cleanKey);
    const label = existing ? existing.label : null;

    db.prepare(`
      INSERT INTO active_sessions (hwid, key, label, app_type, video_id, video_title, channel_name, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(hwid) DO UPDATE SET
        key=excluded.key,
        label=COALESCE(excluded.label, active_sessions.label),
        app_type=excluded.app_type,
        video_id=CASE WHEN excluded.video_id != '' THEN excluded.video_id ELSE active_sessions.video_id END,
        video_title=CASE WHEN excluded.video_title != '' THEN excluded.video_title ELSE active_sessions.video_title END,
        channel_name=CASE WHEN excluded.channel_name != '' THEN excluded.channel_name ELSE active_sessions.channel_name END,
        last_seen=datetime('now')
    `).run(cleanHwid, cleanKey, label, app_type, video_id, video_title, channel_name);
  } catch (err) {
    console.error("Session update error:", err);
  }

  // Fetch undelivered messages for this device
  let pendingMessages = [];
  try {
    const allMsgs = db.prepare("SELECT * FROM messages ORDER BY id ASC").all();
    for (const msg of allMsgs) {
      if (msg.target_hwid && msg.target_hwid !== "ALL" && msg.target_hwid !== cleanHwid) {
        continue;
      }
      let delivered = [];
      try { delivered = JSON.parse(msg.delivered_to || "[]"); } catch (_) {}
      if (!delivered.includes(cleanHwid)) {
        pendingMessages.push({
          id: msg.id,
          title: msg.title,
          message: msg.message,
          type: msg.type
        });
        delivered.push(cleanHwid);
        db.prepare("UPDATE messages SET delivered_to = ? WHERE id = ?").run(JSON.stringify(delivered), msg.id);
      }
    }
  } catch (err) {
    console.error("Message retrieval error:", err);
  }

  return res.json({
    status: "VALID",
    messages: pendingMessages
  });
});

// Report bypass attempt
app.post("/api/report-bypass", (req, res) => {
  const { hwid, key } = req.body || {};
  if (!hwid) return res.sendStatus(400);
  try {
    db.prepare("INSERT OR IGNORE INTO banned_hwids (hwid, reason) VALUES (?, ?)").run(hwid, "Auto-ban: server bypass detected");
    if (key) db.prepare("UPDATE keys SET banned=1 WHERE key=?").run(key);
    log("bypass", key || "?", hwid, req.headers["x-forwarded-for"] || req.socket.remoteAddress, "AUTO_BANNED");
  } catch (_) {}
  return res.json({ status: "ok" });
});

// ─── ADMIN API ───────────────────────────────────────────────────────────────

// Generate key
app.post("/admin/keys/generate", adminGuard, (req, res) => {
  const { duration = "30d", label = "" } = req.body || {};
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
  const { key } = req.body || {};
  db.prepare("UPDATE keys SET banned=1 WHERE key=?").run((key || "").trim().toUpperCase());
  res.json({ status: "ok" });
});

// Reset key (unbind HWID for device transfer)
app.post("/admin/keys/reset", adminGuard, (req, res) => {
  const { key } = req.body || {};
  const cleanKey = (key || "").trim().toUpperCase();
  db.prepare("UPDATE keys SET activated=0, hwid=NULL, activated_at=NULL, expires_at=NULL WHERE key=?").run(cleanKey);
  res.json({ status: "ok", key: cleanKey });
});

// Live Active Sessions (What users are watching right now)
app.get("/admin/sessions", adminGuard, (req, res) => {
  const sessions = db.prepare(`
    SELECT s.*, 
           CASE WHEN datetime(s.last_seen) >= datetime('now', '-60 seconds') THEN 1 ELSE 0 END AS is_online
    FROM active_sessions s
    ORDER BY s.last_seen DESC
  `).all();
  res.json(sessions);
});

// Clear inactive sessions
app.post("/admin/sessions/clear", adminGuard, (req, res) => {
  db.prepare("DELETE FROM active_sessions WHERE datetime(last_seen) < datetime('now', '-2 hours')").run();
  res.json({ status: "ok" });
});

// Send Push Message to user(s)
app.post("/admin/messages/send", adminGuard, (req, res) => {
  const { target_hwid = "ALL", title = "Admin Értesítés", message, type = "toast" } = req.body || {};
  if (!message || !message.trim()) {
    return res.status(400).json({ error: "Message is required" });
  }

  const result = db.prepare(`
    INSERT INTO messages (target_hwid, title, message, type, delivered_to)
    VALUES (?, ?, ?, ?, '[]')
  `).run(target_hwid, title.trim(), message.trim(), type);

  log("message_sent", target_hwid, target_hwid, req.headers["x-forwarded-for"] || req.socket.remoteAddress, `ID:${result.lastInsertRowid}`);
  res.json({ status: "ok", id: result.lastInsertRowid });
});

// List messages
app.get("/admin/messages", adminGuard, (req, res) => {
  const list = db.prepare("SELECT * FROM messages ORDER BY id DESC LIMIT 50").all();
  res.json(list);
});

// Delete message
app.post("/admin/messages/delete", adminGuard, (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: "id required" });
  db.prepare("DELETE FROM messages WHERE id = ?").run(id);
  res.json({ status: "ok" });
});

// HWID Ban
app.post("/admin/ban", adminGuard, (req, res) => {
  const { hwid, reason = "Manual ban by admin" } = req.body || {};
  if (!hwid) return res.status(400).json({ error: "hwid required" });
  db.prepare("INSERT OR IGNORE INTO banned_hwids (hwid, reason) VALUES (?, ?)").run(hwid, reason);
  db.prepare("UPDATE keys SET banned=1 WHERE hwid=?").run(hwid);
  res.json({ status: "ok", hwid });
});

// HWID Unban
app.post("/admin/unban", adminGuard, (req, res) => {
  const { hwid } = req.body || {};
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
