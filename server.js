"use strict";
// Hasba local server: static files + JSON API + SQLite (node:sqlite). No third-party dependencies.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const PUB = path.join(__dirname, "public");
const SESSION_DAYS = 7;

fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });
const db = new DatabaseSync(path.join(__dirname, "data", "hasba.db"));
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE NOT NULL, phone TEXT, pass_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'USER', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, ua TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS consents(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL, version TEXT NOT NULL, granted_at TEXT NOT NULL, ip TEXT);
CREATE TABLE IF NOT EXISTS states(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, json TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL, user_id INTEGER, action TEXT NOT NULL, ip TEXT);
`);

const now = () => new Date().toISOString();
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const log = (uid, action, ip) => db.prepare("INSERT INTO audit(at,user_id,action,ip) VALUES(?,?,?,?)").run(now(), uid, action, ip);

function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString("hex")}$${h.toString("hex")}`;
}
function checkPw(pw, stored) {
  const [alg, s, h] = String(stored).split("$");
  if (alg !== "scrypt") return false;
  const calc = crypto.scryptSync(pw, Buffer.from(s, "hex"), 64, { N: 16384, r: 8, p: 1 });
  const exp = Buffer.from(h, "hex");
  return calc.length === exp.length && crypto.timingSafeEqual(calc, exp);
}
const DUMMY = hashPw("dummy-password-for-timing");

// login throttling: 5 failures per 15 minutes per email+ip
const fails = new Map();
const throttled = (k) => { const f = fails.get(k); return f && f.n >= 5 && Date.now() - f.t < 15 * 60e3; };
const failed = (k) => { const f = fails.get(k); fails.set(k, !f || Date.now() - f.t > 15 * 60e3 ? { n: 1, t: Date.now() } : { n: f.n + 1, t: f.t }); };

function send(res, code, obj, headers = {}) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on("data", (c) => { n += c.length; if (n > 1e6) { reject(Object.assign(new Error("big"), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch { reject(Object.assign(new Error("json"), { code: 400 })); } });
    req.on("error", reject);
  });
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || "").split(";").forEach((p) => { const i = p.indexOf("="); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
const cookieStr = (v, maxAge) => `hasba_sid=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
function userFrom(req) {
  const tok = cookies(req).hasba_sid;
  if (!tok) return null;
  const row = db.prepare("SELECT u.id,u.name,u.email,u.role,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?").get(sha(tok));
  if (!row) return null;
  if (row.expires_at < Date.now()) { db.prepare("DELETE FROM sessions WHERE token_hash=?").run(sha(tok)); return null; }
  return row;
}
function startSession(req, uid) {
  const tok = crypto.randomBytes(32).toString("base64url");
  db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,ua,ip) VALUES(?,?,?,?,?)").run(sha(tok), uid, Date.now() + SESSION_DAYS * 864e5, String(req.headers["user-agent"] || "").slice(0, 200), req.socket.remoteAddress);
  return cookieStr(tok, SESSION_DAYS * 86400);
}
const pub = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const validState = (s) => s && typeof s === "object" && Array.isArray(s.subs) && s.subs.length <= 500 && Array.isArray(s.finds) && s.finds.length <= 500 && s.settings && typeof s.settings === "object";
const getState = (uid) => { const r = db.prepare("SELECT json FROM states WHERE user_id=?").get(uid); return r ? JSON.parse(r.json) : null; };
const putState = (uid, s) => db.prepare("INSERT INTO states(user_id,json,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET json=excluded.json,updated_at=excluded.updated_at").run(uid, JSON.stringify(s), now());

async function api(req, res, url) {
  const ip = req.socket.remoteAddress, m = req.method, p = url.pathname.slice(4);
  if (m !== "GET" && (req.headers["x-requested-with"] !== "hasba" || !String(req.headers["content-type"] || "").includes("application/json")))
    return send(res, 403, { error: "csrf" });
  const body = m === "GET" ? {} : await readBody(req);

  if (p === "/signup" && m === "POST") {
    const email = String(body.email || "").trim().toLowerCase(), pw = String(body.password || "");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 200) return send(res, 400, { error: "email" });
    if (pw.length < 10 || pw.length > 200) return send(res, 400, { error: "password" });
    const need = ["privacy", "data", "ai"];
    if (!Array.isArray(body.consents) || !need.every((c) => body.consents.includes(c))) return send(res, 400, { error: "consent" });
    if (db.prepare("SELECT 1 FROM users WHERE email=?").get(email)) return send(res, 409, { error: "exists" });
    const r = db.prepare("INSERT INTO users(name,email,phone,pass_hash,role,created_at) VALUES(?,?,?,?,'USER',?)").run(String(body.name || "").slice(0, 100), email, String(body.phone || "").slice(0, 30), hashPw(pw), now());
    const uid = Number(r.lastInsertRowid);
    need.forEach((c) => db.prepare("INSERT INTO consents(user_id,type,version,granted_at,ip) VALUES(?,?,?,?,?)").run(uid, c, "draft-1", now(), ip));
    if (validState(body.state)) putState(uid, body.state);
    log(uid, "signup", ip);
    return send(res, 201, { user: { id: uid, name: String(body.name || ""), email, role: "USER" }, state: getState(uid) }, { "Set-Cookie": startSession(req, uid) });
  }
  if (p === "/login" && m === "POST") {
    const email = String(body.email || "").trim().toLowerCase(), key = email + "|" + ip;
    if (throttled(key)) return send(res, 429, { error: "throttled" });
    const u = db.prepare("SELECT * FROM users WHERE email=?").get(email);
    const ok = checkPw(String(body.password || ""), u ? u.pass_hash : DUMMY) && !!u;
    if (!ok) { failed(key); log(u ? u.id : null, "login_failed", ip); return send(res, 401, { error: "credentials" }); }
    fails.delete(key); log(u.id, "login", ip);
    return send(res, 200, { user: pub(u), state: getState(u.id) }, { "Set-Cookie": startSession(req, u.id) });
  }
  if (p === "/logout" && m === "POST") {
    const tok = cookies(req).hasba_sid;
    if (tok) db.prepare("DELETE FROM sessions WHERE token_hash=?").run(sha(tok));
    return send(res, 200, { ok: true }, { "Set-Cookie": cookieStr("", 0) });
  }
  const u = userFrom(req);
  if (p === "/me" && m === "GET") return u ? send(res, 200, { user: pub(u), state: getState(u.id) }) : send(res, 200, { user: null });
  if (!u) return send(res, 401, { error: "auth" });

  if (p === "/state" && m === "PUT") {
    if (!validState(body)) return send(res, 400, { error: "state" });
    putState(u.id, body);
    return send(res, 200, { ok: true });
  }
  if (p === "/export" && m === "GET") {
    return send(res, 200, { user: pub(u), exported_at: now(), state: getState(u.id), consents: db.prepare("SELECT type,version,granted_at FROM consents WHERE user_id=?").all(u.id) });
  }
  if (p === "/account" && m === "DELETE") {
    const row = db.prepare("SELECT pass_hash FROM users WHERE id=?").get(u.id);
    if (!checkPw(String(body.password || ""), row.pass_hash)) return send(res, 401, { error: "credentials" });
    log(u.id, "account_deleted", ip);
    db.prepare("DELETE FROM users WHERE id=?").run(u.id);
    return send(res, 200, { ok: true }, { "Set-Cookie": cookieStr("", 0) });
  }
  return send(res, 404, { error: "not_found" });
}

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json" };
const SEC = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "X-Frame-Options": "DENY",
};
http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    Object.entries(SEC).forEach(([k, v]) => res.setHeader(k, v));
    if (url.pathname.startsWith("/api/")) return await api(req, res, url);
    let f = path.normalize(path.join(PUB, decodeURIComponent(url.pathname)));
    if (!f.startsWith(PUB)) { res.writeHead(403); return res.end(); }
    if (url.pathname === "/" || !fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(PUB, "index.html");
    res.writeHead(200, { "Content-Type": MIME[path.extname(f)] || "application/octet-stream", "Cache-Control": "no-cache" });
    fs.createReadStream(f).pipe(res);
  } catch (e) {
    if (!res.headersSent) send(res, e.code === 413 || e.code === 400 ? e.code : 500, { error: e.code ? e.message : "server" });
    if (!e.code) console.error(e);
  }
}).listen(PORT, HOST, () => console.log(`Hasba running at http://localhost:${PORT}`));
