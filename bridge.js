// bridge.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const { Readable } = require("stream");
const crypto = require("crypto");

const app = express();

const PORT = 5055;
const SCANNER_HOST = "http://192.168.101.1";

const DATA_DIR = __dirname;
const CHECKS_FILE = path.join(DATA_DIR, "checks.json");
const APPINST_FILE = path.join(DATA_DIR, "appinstid.txt");

app.use(express.json({ limit: "2mb" }));

let phpSessId = null;

// -------------------- persistence helpers --------------------
function readTextFileSafe(p) {
  try {
    const s = fs.readFileSync(p, "utf8").trim();
    return s || null;
  } catch {
    return null;
  }
}

function writeTextFileSafe(p, s) {
  try {
    fs.writeFileSync(p, s, "utf8");
  } catch {}
}

function isGuidLike(s) {
  if (!s || typeof s !== "string") return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

let appInstId = readTextFileSafe(APPINST_FILE) || crypto.randomUUID();
writeTextFileSafe(APPINST_FILE, appInstId);

function setAppInstId(newId, reason = "") {
  if (!isGuidLike(newId)) return false;
  if (newId.toLowerCase() === appInstId.toLowerCase()) return false;

  appInstId = newId;
  writeTextFileSafe(APPINST_FILE, appInstId);
  console.log(`Learned AppInstId (${reason}): ${appInstId}`);
  return true;
}

function loadChecks() {
  try {
    return JSON.parse(fs.readFileSync(CHECKS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function saveChecks(list) {
  fs.writeFileSync(CHECKS_FILE, JSON.stringify(list, null, 2));
}

let checks = loadChecks();

// -------------------- CORS --------------------
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// -------------------- learn AppInstId from incoming browser requests --------------------
app.use((req, res, next) => {
  const hdr = req.headers["appinstid"];
  if (typeof hdr === "string" && isGuidLike(hdr)) setAppInstId(hdr, "request header");

  const q = req.query?.AppInstId || req.query?.appInstId || req.query?.appinstid;
  if (typeof q === "string" && isGuidLike(q)) setAppInstId(q, "querystring");

  next();
});

// -------------------- scanner fetch helpers --------------------
function captureSetCookie(setCookieHeader) {
  if (!setCookieHeader) return;
  const m = setCookieHeader.match(/PHPSESSID=([^;]+)/);
  if (m) phpSessId = m[1];
}

function scannerHeaders(req, extra = {}) {
  const h = {
    Accept: "*/*",
    "User-Agent": req.headers["user-agent"] || "Mozilla/5.0",
    Referer: `${SCANNER_HOST}/index.html`,
    AppInstId: appInstId,
    ...extra,
  };
  if (phpSessId) h.Cookie = `PHPSESSID=${phpSessId}`;
  return h;
}

function withAppInstQuery(scannerPath) {
  if (!scannerPath || typeof scannerPath !== "string") return scannerPath;
  if (!appInstId) return scannerPath;
  if (scannerPath.includes("AppInstId=")) return scannerPath;

  const joiner = scannerPath.includes("?") ? "&" : "?";
  return `${scannerPath}${joiner}AppInstId=${encodeURIComponent(appInstId)}`;
}

async function fetchScanner(req, scannerPath, opts = {}) {
  const finalPath = withAppInstQuery(scannerPath);
  const url = `${SCANNER_HOST}${finalPath}`;

  const r = await fetch(url, {
    method: opts.method || req.method,
    headers: scannerHeaders(req, opts.headers || {}),
    body: opts.body,
  });

  const setCookie = r.headers.get("set-cookie");
  if (setCookie) captureSetCookie(setCookie);

  return r;
}

function streamFetchToRes(r, res) {
  res.status(r.status);
  const ct = r.headers.get("content-type");
  if (ct) res.setHeader("Content-Type", ct);

  if (!r.body) return res.end();

  const nodeStream = Readable.fromWeb(r.body);
  nodeStream.pipe(res);
}

// -------------------- EverneXt parsing --------------------
function getDocs(state) {
  if (!state || typeof state !== "object") return [];
  if (Array.isArray(state.Documents)) return state.Documents;
  if (Array.isArray(state.Document)) return state.Document;
  if (Array.isArray(state.Docs)) return state.Docs;
  if (Array.isArray(state.DocList)) return state.DocList;
  return [];
}

function parseMicr(micr) {
  if (!micr) return { routing: "", account: "", checkNumber: "" };

  // Example: <066410<:121102036:0066000048<
  const routingMatch = micr.match(/<(\d{9})<:/);
  const routing = routingMatch ? routingMatch[1] : "";

  const parts = micr.split(":");
  let account = "";
  let checkNumber = "";

  if (parts.length >= 3) {
    account = (parts[1] || "").replace(/\D/g, "");
    checkNumber = (parts[2] || "").replace(/\D/g, "");
  }

  return { routing, account, checkNumber };
}

function upsertDocsIntoChecks(stateJson) {
  const docs = getDocs(stateJson);

  for (const d of docs) {
    const id = String(d.ID ?? d.Id ?? "");
    if (!id) continue;

    const existing = checks.find((x) => x.id === id);
    const micr = parseMicr(d.MICR);

    const record = {
      id,
      type: d.Type || "",
      micr: d.MICR || "",
      routing: micr.routing,
      account: micr.account,
      checkNumber: micr.checkNumber,
      frontImage: d.FrontImage1 || "",
      rearImage: d.RearImage1 || "",
      amount: existing?.amount || "",
      scannedAt: existing?.scannedAt || new Date().toISOString(),
    };

    if (!existing) checks.unshift(record);
    else Object.assign(existing, record);
  }

  saveChecks(checks);
}

// -------------------- session priming --------------------
async function primeSession(req) {
  // setup.php reliably sets PHPSESSID
  await fetchScanner(req, "/setup.php", { method: "GET" });
}

async function connectIfNeeded(req) {
  try {
    await fetchScanner(req, "/connect", { method: "GET" });
  } catch {}
}

async function getStateJson(req) {
  const r = await fetchScanner(req, "/currentdevicestateex", { method: "GET" });
  const text = await r.text();
  try {
    return { ok: true, status: r.status, json: JSON.parse(text), raw: text };
  } catch {
    return { ok: false, status: r.status, json: null, raw: text };
  }
}

// -------------------- routes --------------------
app.get("/", (req, res) => {
  res.json({
    ok: true,
    dashboard: `http://localhost:${PORT}/dashboard`,
    ui: `http://localhost:${PORT}/ui/`,
    appInstId,
    hasSession: !!phpSessId,
  });
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/api/init", async (req, res) => {
  try {
    await primeSession(req);
    await connectIfNeeded(req);

    const st = await getStateJson(req);

    res.json({
      ok: true,
      appInstId,
      hasSession: !!phpSessId,
      stateStatus: st.status,
      stateOkJson: st.ok,
      statePreview: st.ok ? { keys: Object.keys(st.json || {}) } : st.raw.slice(0, 200),
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/checks", async (req, res) => {
  try {
    if (!phpSessId) await primeSession(req);
    await connectIfNeeded(req);

    const st = await getStateJson(req);

    if (st.ok && st.json) upsertDocsIntoChecks(st.json);

    res.json({
      ok: true,
      appInstId,
      hasSession: !!phpSessId,
      stateStatus: st.status,
      stateIsJson: st.ok,
      checks,
      lastRaw: st.ok ? null : st.raw,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/image", async (req, res) => {
  try {
    const imgPath = req.query.path;
    if (!imgPath || typeof imgPath !== "string" || !imgPath.startsWith("/images/")) {
      return res.status(400).send("Missing or invalid path (must start with /images/)");
    }
    if (!phpSessId) await primeSession(req);

    const r = await fetchScanner(req, imgPath, { method: "GET" });
    streamFetchToRes(r, res);
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// -------------------- UI reverse proxy --------------------
app.use("/ui", async (req, res) => {
  try {
    if (!phpSessId) await primeSession(req);

    const subPath = req.originalUrl.replace(/^\/ui/, "") || "/";
    const scannerPath = subPath === "/" ? "/index.html" : subPath;

    const r = await fetchScanner(req, scannerPath, { method: "GET" });

    const ct = r.headers.get("content-type") || "";

    if (scannerPath === "/index.html" || ct.includes("text/html")) {
      const html = await r.text();
      const rewritten = html
        .replace(/href="\//g, 'href="/ui/')
        .replace(/src="\//g, 'src="/ui/')
        .replace(/action="\//g, 'action="/ui/');

      res.setHeader("Content-Type", "text/html");
      return res.send(rewritten);
    }

    streamFetchToRes(r, res);
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// -------------------- Proxy root endpoints (UI expects /connect, /logstatus, etc) --------------------
app.use(async (req, res, next) => {
  if (
    req.path.startsWith("/api") ||
    req.path.startsWith("/ui") ||
    req.path === "/dashboard" ||
    req.path === "/"
  ) {
    return next();
  }

  try {
    if (!phpSessId) await primeSession(req);

    const qs = req.originalUrl.includes("?")
      ? req.originalUrl.slice(req.originalUrl.indexOf("?"))
      : "";

    const scannerPath = `${req.path}${qs}`;

    const r = await fetchScanner(req, scannerPath, {
      method: req.method,
      body: ["GET", "HEAD"].includes(req.method) ? undefined : JSON.stringify(req.body || {}),
      headers: ["GET", "HEAD"].includes(req.method)
        ? {}
        : { "Content-Type": req.headers["content-type"] || "application/json" },
    });

    const ct = r.headers.get("content-type") || "";
    if (ct.includes("text/") || ct.includes("json")) {
      const text = await r.text();
      res.status(r.status);
      if (ct) res.setHeader("Content-Type", ct);
      return res.send(text);
    }

    streamFetchToRes(r, res);
  } catch (e) {
    res.status(500).send(String(e));
  }
});

app.listen(PORT, () => {
  console.log(`Bridge running on http://localhost:${PORT}`);
  console.log(`UI: http://localhost:${PORT}/ui/`);
  console.log(`Dashboard: http://localhost:${PORT}/dashboard`);
  console.log(`AppInstId (persistent): ${appInstId}`);
});