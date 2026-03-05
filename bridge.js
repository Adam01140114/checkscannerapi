const express = require("express");
const { Readable } = require("stream");

const app = express();
const PORT = 5055;
const SCANNER_HOST = "http://192.168.101.1";

let appInstId = "D27CDB6E-AE6D-11cf-96B8-444553540000";
let phpSessId = null;

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
}

function streamFetchBodyToRes(fetchResponse, res) {
  if (!fetchResponse.body) return res.end();
  const nodeStream = Readable.fromWeb(fetchResponse.body);
  nodeStream.on("error", () => res.end());
  nodeStream.pipe(res);
}

async function readIncomingBody(req) {
  // Only for methods that can have a body
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return null;

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (chunks.length === 0) return null;
  return Buffer.concat(chunks);
}

app.use((req, res, next) => {
  setCors(res);
  if (req.method === "OPTIONS") return res.sendStatus(204);

  const incoming =
    req.headers["appinstid"] ||
    req.query.AppInstId ||
    req.query.appInstId ||
    req.query.appinstid;

  if (incoming && typeof incoming === "string" && incoming.length >= 8) {
    if (incoming !== appInstId) {
      console.log("Learned AppInstId:", incoming);
      appInstId = incoming;
    }
  }

  next();
});

function buildScannerUrl(path, req) {
  const url = new URL(`${SCANNER_HOST}${path}`);

  // copy query params exactly
  for (const [k, v] of Object.entries(req.query || {})) {
    url.searchParams.set(k, v);
  }

  // ensure AppInstId exists
  if (!url.searchParams.has("AppInstId")) {
    url.searchParams.set("AppInstId", appInstId);
  }

  return url.toString();
}

function scannerHeaders(req, extra = {}) {
  const h = {
    AppInstId: appInstId,
    Referer: `${SCANNER_HOST}/index.html`,
    Accept: "*/*",
    "User-Agent": "Mozilla/5.0",
    ...extra,
  };

  // Forward content-type if browser sent one (needed for POST endpoints)
  const ct = req.headers["content-type"];
  if (ct) h["Content-Type"] = ct;

  // Some scanners care about X-Requested-With (XHR)
  if (req.headers["x-requested-with"]) {
    h["X-Requested-With"] = req.headers["x-requested-with"];
  } else {
    h["X-Requested-With"] = "XMLHttpRequest";
  }

  if (phpSessId) h.Cookie = `PHPSESSID=${phpSessId}`;
  return h;
}

async function fetchScanner(req, path, extraHeaders = {}) {
  const url = buildScannerUrl(path, req);

  const body = await readIncomingBody(req);

  const opts = {
    method: req.method || "GET",
    headers: scannerHeaders(req, extraHeaders),
    body: body ?? undefined,
  };

  const r = await fetch(url, opts);

  const setCookie = r.headers.get("set-cookie");
  if (setCookie) {
    const m = setCookie.match(/PHPSESSID=([^;]+)/);
    if (m) phpSessId = m[1];
  }

  return { r, url };
}

async function primeSession() {
  const fakeReq = {
    method: "GET",
    query: {},
    headers: { "x-requested-with": "XMLHttpRequest" },
    [Symbol.asyncIterator]: async function* () {},
  };

  await fetchScanner(fakeReq, "/setup.php", { Referer: `${SCANNER_HOST}/setup.php` });
  await fetchScanner(fakeReq, "/index.html", { Referer: `${SCANNER_HOST}/index.html` });
}

primeSession().catch(() => {});

app.get("/", (req, res) => {
  res.json({
    ui: `http://localhost:${PORT}/ui`,
    appInstId,
    hasSession: !!phpSessId,
  });
});

// Serve UI without redirect loops
app.get(["/ui", "/ui/"], async (req, res) => {
  const { r } = await fetchScanner(req, "/index.html");
  const html = await r.text();
  const patched = html.replace(/<head>/i, `<head><base href="/ui/">`);

  res.status(r.status);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(patched);
});

// Proxy everything under /ui
app.use("/ui", async (req, res) => {
  let path = req.originalUrl.replace(/^\/ui/, "");
  if (!path || path === "/") path = "/index.html";

  const { r } = await fetchScanner(req, path);

  const ct = r.headers.get("content-type") || "";
  res.status(r.status);
  if (ct) res.setHeader("Content-Type", ct);

  if (ct.includes("text/html")) {
    const html = await r.text();
    const patched = html.replace(/<head>/i, `<head><base href="/ui/">`);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(patched);
  }

  if (!r.ok && ct.includes("text")) {
    return res.send(await r.text());
  }

  streamFetchBodyToRes(r, res);
});

// Proxy scanner endpoints that the UI calls from root paths
const ROOT_PROXY_PREFIXES = [
  "/skins/",
  "/images/",
  "/currentdevicestate",
  "/currentdevicestateex",
  "/deviceinformation",
  "/logstatus",
  "/connect",
  "/scan",
  "/userdata/",
  "/time",
  "/usermsg",
  "/removeitemrange",
  "/removeitem",
  "/removeitems",
];

app.use(async (req, res, next) => {
  const hit = ROOT_PROXY_PREFIXES.some((p) => req.path === p || req.path.startsWith(p));
  if (!hit) return next();

  const { r } = await fetchScanner(req, req.originalUrl);

  const ct = r.headers.get("content-type") || "";
  res.status(r.status);
  if (ct) res.setHeader("Content-Type", ct);

  if (!r.ok && ct.includes("text")) {
    return res.send(await r.text());
  }

  streamFetchBodyToRes(r, res);
});

app.listen(PORT, () => {
  console.log(`Bridge running on http://localhost:${PORT}`);
  console.log(`Open UI through bridge: http://localhost:${PORT}/ui`);
});