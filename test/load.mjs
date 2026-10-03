// Local functional + load test against `wrangler dev`.
import WebSocket from "ws";
import crypto from "node:crypto";

const BASE = process.env.BASE ?? "ws://127.0.0.1:8787";
const SECRET = "test-secret-123";
const ORIGIN = "https://wordalive.app";
const ROOM = `owner-${Date.now()}:sess-1`;
const VIEWERS = Number(process.env.VIEWERS ?? 50);

const tok = (room, role, exp = Math.floor(Date.now() / 1000) + 3600) =>
  `${exp}.${crypto.createHmac("sha256", SECRET).update(`${room}|${role}|${exp}`).digest("base64url")}`;

function open(role, { token, thumbs, origin = ORIGIN, room = ROOM } = {}) {
  const q = new URLSearchParams({ role });
  if (token) q.set("token", token);
  if (thumbs) q.set("thumbs", "1");
  const ws = new WebSocket(`${BASE}/room/${encodeURIComponent(room)}?${q}`, { headers: { Origin: origin } });
  const c = { ws, role, got: {}, frames: [], status: null };
  ws.on("message", (d) => {
    const s = d.toString();
    if (s === "pong") { c.got.pong = (c.got.pong ?? 0) + 1; return; }
    const m = JSON.parse(s);
    c.got[m.e] = (c.got[m.e] ?? 0) + 1;
    c.frames.push(m);
  });
  let resolveReady; ws.on("unexpected-response", (_req, res) => { c.status = res.statusCode; resolveReady?.(false); });
  c.ready = new Promise((r) => { resolveReady = r; ws.on("open", () => r(true)); ws.on("error", () => r(false)); ws.on("close", () => r(false)); });
  return c;
}
const send = (c, e, p) => c.ws.send(JSON.stringify({ e, p }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let fails = 0;
const check = (name, ok, detail = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`); if (!ok) fails++; };

// 1. auth
const bad = open("host", { token: "123.bad" }); await bad.ready;
check("host without valid token rejected", bad.status === 401, `status ${bad.status}`);
const badOrigin = open("viewer", { origin: "https://evil.example" }); await badOrigin.ready;
check("foreign origin rejected", badOrigin.status === 403, `status ${badOrigin.status}`);
const fakeCtl = open("control", { token: tok(ROOM, "host") }); await fakeCtl.ready;
check("host token cannot be reused as control", fakeCtl.status === 401);

// 2. connect
const host = open("host", { token: tok(ROOM, "host") });
check("host connects", await host.ready);
const control = open("control", { token: tok(ROOM, "control"), thumbs: true });
const displays = [open("display"), open("display")];
const viewers = Array.from({ length: VIEWERS }, () => open("viewer"));
const all = [control, ...displays, ...viewers];
const okCount = (await Promise.all(all.map((c) => c.ready))).filter(Boolean).length;
check(`${all.length} subscribers connect`, okCount === all.length, `${okCount}/${all.length}`);
await sleep(2000);
const pres = host.frames.filter((f) => f.e === "room:presence").at(-1)?.p;
check("host sees presence counts (no phone traffic)", pres?.viewers === VIEWERS && pres?.displays === 2 && pres?.controls === 1, JSON.stringify(pres));
check("viewers never receive presence", viewers.every((v) => !v.got["room:presence"]));

// 3. snapshot stream: 2/s, ~9 KB, 10 s
const line = (i) => ({ id: `l${i}`, source: "가".repeat(60), translated: "word ".repeat(40) });
const t0 = Date.now();
for (let i = 0; i < 20; i++) {
  send(host, "snapshot", { seq: i, lines: Array.from({ length: 30 }, (_, k) => line(i * 30 + k)), sentAt: Date.now() });
  await sleep(500);
}
await sleep(800);
const counts = viewers.map((v) => v.got.snapshot ?? 0);
check("every viewer got all 20 snapshots", counts.every((n) => n === 20), `min ${Math.min(...counts)} max ${Math.max(...counts)}`);
const lastFrames = viewers.map((v) => v.frames.filter((f) => f.e === "snapshot").at(-1));
check("viewers hold latest state", lastFrames.every((f) => f?.p?.seq === 19));

// 4. late joiner gets state immediately, without involving the host
const hostBefore = { ...host.got };
const late = open("viewer"); await late.ready; await sleep(300);
check("late viewer receives stored snapshot on join", late.frames.find((f) => f.e === "snapshot")?.p?.seq === 19);
send(late, "request", {}); await sleep(300);
check("request answered to asker only", (late.got.snapshot ?? 0) === 2 && viewers.every((v) => v.got.snapshot === 20));
check("host never sees request", !host.got.request && host.got.snapshot === hostBefore.snapshot);

// 5. display heartbeats go to host + control only
send(displays[0], "display:heartbeat", { id: "d0" });
send(viewers[0], "display:heartbeat", { id: "phone0" });
await sleep(300);
check("display heartbeat reaches host", host.got["display:heartbeat"] === 2);
check("display heartbeat reaches control", control.got["display:heartbeat"] === 2);
check("other phones/displays do not get heartbeats", viewers.slice(1).every((v) => !v.got["display:heartbeat"]) && !displays[1].got["display:heartbeat"]);

// 6. commands
send(viewers[1], "command", { type: "next" });
send(control, "command", { type: "prev" });
await sleep(300);
check("anonymous viewer command dropped, control command delivered", host.got.command === 1 && host.frames.find((f) => f.e === "command")?.p?.type === "prev");

// 7. host → displays (tts / override)
send(host, "display:tts", { url: "x" }); await sleep(300);
check("host display:* fans out to subscribers", displays.every((d) => d.got["display:tts"] === 1));
send(control, "display:override", { target: "d1" }); await sleep(300);
check("control display:override reaches displays", displays.every((d) => d.got["display:override"] === 1));

// 8. thumbs only to thumbs=1 sockets, and replayed on join
send(host, "thumbs", { items: [{ id: "s1", thumb: "data:image/png;base64," + "A".repeat(50_000) }, { id: "s2", thumb: "data:x" }] });
await sleep(300);
check("thumbs go to control only", control.got.thumbs === 1 && viewers.every((v) => !v.got.thumbs));
const ctl2 = open("control", { token: tok(ROOM, "control"), thumbs: true }); await ctl2.ready; await sleep(300);
check("new control gets stored thumbs on join", ctl2.frames.find((f) => f.e === "thumbs")?.p?.items?.length === 2);

// 9. keepalive auto-response
viewers[2].ws.send("ping"); await sleep(200);
check("ping → pong auto-response", viewers[2].got.pong === 1);

// 10. load: 2 snapshots/s for 30 s to N viewers, measure delivery latency
const lat = [];
for (const v of viewers) v.ws.on("message", (d) => { const s = d.toString(); if (s[0] !== "{") return; const m = JSON.parse(s); if (m.e === "snapshot" && m.p?.load) lat.push(Date.now() - m.p.sentAt); });
for (let i = 0; i < 60; i++) {
  send(host, "snapshot", { load: true, seq: 100 + i, lines: Array.from({ length: 30 }, (_, k) => line(k)), sentAt: Date.now() });
  await sleep(500);
}
await sleep(1000);
lat.sort((a, b) => a - b);
const p = (q) => lat[Math.min(lat.length - 1, Math.floor(q * lat.length))];
check(`load: ${VIEWERS} viewers × 60 snapshots delivered`, lat.length === VIEWERS * 60, `${lat.length} frames, p50 ${p(0.5)}ms p95 ${p(0.95)}ms max ${lat.at(-1)}ms`);

// 11. host reconnect: viewers keep state, presence updates
host.ws.close(); await sleep(2200);
const ctlPres = control.frames.filter((f) => f.e === "room:presence").at(-1)?.p;
check("control sees host gone", ctlPres?.host === 0, JSON.stringify(ctlPres));
const host2 = open("host", { token: tok(ROOM, "host") }); await host2.ready;
send(host2, "snapshot", { seq: 999, lines: [] }); await sleep(300);
check("reconnected host resumes stream", viewers.every((v) => v.frames.filter((f) => f.e === "snapshot").at(-1)?.p?.seq === 999));

console.log(fails ? `\n${fails} FAILED` : "\nALL PASSED");
for (const c of [host2, ctl2, late, ...all]) try { c.ws.close(); } catch {}
process.exit(fails ? 1 : 0);
