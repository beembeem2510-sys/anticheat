// server.js — backend ของแดชบอร์ด anti-cheat + ระบบสแกนเครื่องผู้เล่น (Node 18+ ไม่ต้องติดตั้งแพ็กเกจ)
// รัน:  API_KEY=xxxx ADMIN_PASSWORD=yyyy node server.js
// ต้องวางหลัง HTTPS (เช่น Cloudflare / Nginx / Render / Railway) เพราะ Roblox เรียกได้เฉพาะ HTTPS

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const DB_FILE = path.join(__dirname, "data.json");

if (!API_KEY || !ADMIN_PASSWORD) {
  console.error("ตั้งค่า API_KEY และ ADMIN_PASSWORD ผ่าน environment ก่อน");
  process.exit(1);
}

let db = { events: [], players: {}, actions: [], scans: [], nextId: 1 };
try {
  db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
} catch {}
db.events ||= [];
db.players ||= {};
db.actions ||= [];
db.scans ||= [];
db.nextId ||= 1;

let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => fs.writeFile(DB_FILE, JSON.stringify(db), () => {}), 500);
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 1e6) {
        reject(new Error("too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
  });
}

function send(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function readLocal(name) {
  return fs.readFileSync(path.join(__dirname, name), "utf8");
}

// จำกัดการลองรหัสผ่านแอดมินผิดซ้ำ
const failures = new Map();
function adminOk(req) {
  const ip = req.socket.remoteAddress;
  const f = failures.get(ip) || { n: 0, until: 0 };
  if (Date.now() < f.until) return false;
  if (safeEqual(req.headers["x-admin"] || "", ADMIN_PASSWORD)) {
    failures.delete(ip);
    return true;
  }
  f.n += 1;
  if (f.n >= 5) {
    f.until = Date.now() + 5 * 60 * 1000;
    f.n = 0;
  }
  failures.set(ip, f);
  return false;
}
const keyOk = (req) => safeEqual(req.headers["x-api-key"] || "", API_KEY);

// จำกัดจำนวนครั้งที่ส่งผลสแกน (กันสแปม) — 8 ครั้ง / 10 นาที / IP
const clientIp = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
const scanHits = new Map();
function scanRateOk(ip) {
  const now = Date.now();
  const list = (scanHits.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  if (list.length >= 8) {
    scanHits.set(ip, list);
    return false;
  }
  list.push(now);
  scanHits.set(ip, list);
  return true;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const p = url.pathname;

    // ---------- หน้าเว็บ ----------
    if (req.method === "GET" && (p === "/" || p === "/index.html")) {
      const html = readLocal("dashboard.html");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(html);
    }

    // หน้าสำหรับผู้เล่น: อธิบาย + ดาวน์โหลดตัวสแกน
    if (req.method === "GET" && p === "/scan") {
      const html = readLocal("scan.html");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(html);
    }

    // ไฟล์ตัวสแกน: ใส่ที่อยู่เซิร์ฟเวอร์นี้ลงไปให้อัตโนมัติ
    if (req.method === "GET" && p === "/scanner.ps1") {
      const host = String(req.headers.host || "");
      if (!/^[a-z0-9.\-:]+$/i.test(host)) return send(res, 400, { error: "bad host" });
      const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim() === "https" ? "https" : "http";
      const script = readLocal("scanner.ps1").replace(/__SERVER__/g, proto + "://" + host);
      res.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="scanner.ps1"',
      });
      return res.end(script);
    }

    // ---------- ระบบสแกนเครื่อง (ผู้เล่นรันตัวสแกนเอง) ----------
    if (p === "/api/scan/blacklist" && req.method === "GET") {
      return send(res, 200, JSON.parse(readLocal("blacklist.json")));
    }

    if (p === "/api/scan/submit" && req.method === "POST") {
      if (!scanRateOk(clientIp(req))) return send(res, 429, { error: "too many requests" });
      const b = await readBody(req);
      const code = String(b.code || "").toUpperCase();
      const name = String(b.name || "");
      if (!/^[A-Z2-9]{6}$/.test(code)) return send(res, 400, { error: "bad code" });
      if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return send(res, 400, { error: "bad name" });
      const rawHits = Array.isArray(b.hits) ? b.hits : b.hits ? [b.hits] : [];
      const hits = rawHits.slice(0, 50).map((h) => ({
        type: ["process", "window", "file"].includes(h.type) ? h.type : "other",
        severity: h.severity === "high" ? "high" : "warn",
        label: String(h.label || "").slice(0, 60),
        match: String(h.match || "").slice(0, 80),
      }));
      db.scans.push({
        id: db.nextId++,
        time: Math.floor(Date.now() / 1000),
        code,
        name,
        hits,
        scanned: Number(b.scanned) || 0,
        v: Number(b.v) || 1,
      });
      if (db.scans.length > 2000) db.scans = db.scans.slice(-2000);
      save();
      return send(res, 200, { ok: true });
    }

    // ---------- จากเกม Roblox ----------
    if (p === "/api/report" && req.method === "POST") {
      if (!keyOk(req)) return send(res, 401, { error: "bad key" });
      const body = await readBody(req);
      for (const e of (body.events || []).slice(0, 200)) {
        const ev = {
          id: db.nextId++,
          userId: Number(e.userId),
          name: String(e.name || "").slice(0, 40),
          kind: String(e.kind || "").slice(0, 20),
          detail: String(e.detail || "").slice(0, 200),
          strikes: Number(e.strikes) || 0,
          jobId: String(e.jobId || "").slice(0, 60),
          time: Number(e.time) || Math.floor(Date.now() / 1000),
        };
        db.events.push(ev);
        const pl = (db.players[ev.userId] ||= { userId: ev.userId, name: ev.name, counts: {}, last: 0, banned: false });
        pl.name = ev.name;
        pl.last = ev.time;
        pl.counts[ev.kind] = (pl.counts[ev.kind] || 0) + 1;
        if (ev.kind === "ban") pl.banned = true;
      }
      if (db.events.length > 5000) db.events = db.events.slice(-5000);
      save();
      return send(res, 200, { ok: true });
    }

    if (p === "/api/actions" && req.method === "GET") {
      if (!keyOk(req)) return send(res, 401, { error: "bad key" });
      return send(res, 200, { actions: db.actions.filter((a) => !a.done) });
    }

    if (p === "/api/actions/ack" && req.method === "POST") {
      if (!keyOk(req)) return send(res, 401, { error: "bad key" });
      const body = await readBody(req);
      const ids = new Set(body.ids || []);
      db.actions.forEach((a) => ids.has(a.id) && (a.done = true));
      db.actions = db.actions.filter((a) => !a.done || Date.now() - a.created < 86400000);
      save();
      return send(res, 200, { ok: true });
    }

    // ---------- จากแดชบอร์ด ----------
    if (p.startsWith("/api/admin/")) {
      if (!adminOk(req)) return send(res, 401, { error: "unauthorized" });

      if (p === "/api/admin/overview" && req.method === "GET") {
        const players = Object.values(db.players).sort((a, b) => b.last - a.last).slice(0, 200);
        return send(res, 200, {
          players,
          events: db.events.slice(-150).reverse(),
          scans: db.scans.slice(-100).reverse(),
        });
      }

      if ((p === "/api/admin/ban" || p === "/api/admin/kick") && req.method === "POST") {
        const body = await readBody(req);
        const userId = Number(body.userId);
        if (!Number.isInteger(userId) || userId <= 0) return send(res, 400, { error: "bad userId" });
        const action = p.endsWith("ban") ? "ban" : "kick";
        db.actions.push({
          id: db.nextId++,
          action,
          userId,
          reason: String(body.reason || "").slice(0, 200),
          seconds: action === "ban" ? Math.max(0, Number(body.seconds) || 0) || undefined : undefined,
          created: Date.now(),
          done: false,
        });
        if (action === "ban" && db.players[userId]) db.players[userId].banned = true;
        save();
        return send(res, 200, { ok: true });
      }
    }

    send(res, 404, { error: "not found" });
  } catch (e) {
    if (res.headersSent) return res.end();
    send(res, 400, { error: String(e.message || e) });
  }
});

server.listen(PORT, () => console.log("AntiCheat dashboard on :" + PORT));
