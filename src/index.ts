/**
 * WORDaLIVE realtime relay — one Durable Object ("Room") per caption channel.
 *
 * Replaces the Supabase broadcast topic `prompter:${ownerId}:${sessionId}`.
 * The room name is exactly the part after "prompter:", so the client keeps
 * its existing channel naming.
 *
 * Wire format (both directions): JSON text frames  { "e": event, "p": payload }
 * Event names are the same as the existing Supabase broadcast events.
 *
 * Routing (the reason this is cheap — nothing fans out that does not need to):
 *   from host     snapshot          → stored, sent to every non-host socket
 *                 thumbs            → stored, sent only to sockets that asked (?thumbs=1)
 *                 anything else     → every non-host socket
 *   from others   request           → answered by the room itself, to the asker only
 *                 command           → host(s) only
 *                 display:*         → host(s) + controllers (never to other phones)
 *                 anything else     → host(s) only
 *   room events   room:hello        → sent on connect: { hasHost, role }
 *                 room:presence     → to host + controllers when counts change
 *                 room:host         → to non-host sockets when the host appears / leaves: { present }
 *
 * Keepalive: clients send the literal text "ping"; the room auto-replies "pong"
 * without waking (hibernation-friendly, not billed as a message).
 */

export interface Env {
  ROOMS: DurableObjectNamespace;
  /** Single "registry" object that collects per-room usage counters for /stats. */
  STATS: DurableObjectNamespace;
  RT_SECRET: string; // shared with the Lovable server function that mints host/control tokens
  ALLOWED_ORIGINS?: string; // comma-separated; empty = allow all
  /** "1" = /control remotes must present a token. Off until the app mints control tokens (today the /control link itself is the key). */
  CONTROL_TOKEN_REQUIRED?: string;
  /** How long after activity a room reports its counters to the registry (default 30000 ms). */
  STATS_REPORT_MS?: string;
}

type Role = "host" | "viewer" | "display" | "control";
interface Attachment {
  role: Role;
  thumbs: boolean;
  at: number;
}

const ROLES: Role[] = ["host", "viewer", "display", "control"];
const ROOM_RE = /^[A-Za-z0-9_\-:.]{1,200}$/;
const PRESENCE_DEBOUNCE_MS = 1500;
const STALE_MS = 10 * 60_000;
const STATS_KEEP_DAYS = 21;

/** Usage counters of one room for one UTC day. Counted per frame, so they track what a metered relay would bill. */
interface RoomStats {
  day: string; // UTC date YYYY-MM-DD
  opened: Record<Role, number>; // sockets opened today, by role
  msgsIn: number; // frames received from clients (keepalive pings are answered by the runtime and not counted)
  msgsOut: number; // frames sent to clients
  peakViewers: number; // most phones (viewer role) connected at once
  peakSockets: number; // most non-host sockets connected at once
  firstAt: number;
  lastAt: number;
}

const utcDay = (t = Date.now()) => new Date(t).toISOString().slice(0, 10);
const freshStats = (): RoomStats => ({
  day: utcDay(),
  opened: { host: 0, viewer: 0, display: 0, control: 0 },
  msgsIn: 0,
  msgsOut: 0,
  peakViewers: 0,
  peakSockets: 0,
  firstAt: Date.now(),
  lastAt: Date.now(),
});
/** Test rooms (/selftest, /diag) never show up in the usage numbers. */
const isCountedRoom = (name: string) => !!name && !name.startsWith("selftest-") && !name.startsWith("diag:");

// ───────────────────────────── token (HMAC-SHA256) ─────────────────────────────
// token = `${exp}.${base64url(HMAC(secret, `${room}|${role}|${exp}`))}`, exp in unix seconds.

const enc = new TextEncoder();

function b64url(buf: ArrayBuffer): string {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmac(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export async function signToken(secret: string, room: string, role: Role, exp: number): Promise<string> {
  return `${exp}.${await hmac(secret, `${room}|${role}|${exp}`)}`;
}

async function verifyToken(secret: string, token: string | null, room: string, role: Role): Promise<boolean> {
  if (!token || !secret) return false;
  const dot = token.indexOf(".");
  if (dot < 1) return false;
  const exp = Number(token.slice(0, dot));
  if (!Number.isFinite(exp) || exp * 1000 < Date.now()) return false;
  const expected = await hmac(secret, `${room}|${role}|${exp}`);
  return safeEqual(expected, token.slice(dot + 1));
}

// ───────────────────────────── Worker entry ─────────────────────────────

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") return new Response("ok");
    if (url.pathname === "/diag") {
      // No secrets revealed: only whether one is set, its length, and an 8-char hash prefix to compare.
      const secret = env.RT_SECRET ?? "";
      const digest = secret ? b64url(await crypto.subtle.digest("SHA-256", enc.encode(secret))).slice(0, 8) : null;
      let room = "unreachable";
      try {
        const r = await env.ROOMS.get(env.ROOMS.idFromName("diag:ping")).fetch("https://do/__ping");
        room = await r.text();
      } catch (e) {
        room = "error: " + String(e);
      }
      return Response.json({ secretSet: !!secret, secretLen: secret.length, secretHash: digest, durableObject: room, origins: env.ALLOWED_ORIGINS ?? "" });
    }
    if (url.pathname === "/stats") {
      // Usage numbers for the operator. The key is derived from RT_SECRET (`hmac(secret, "stats|v1")`, first 24 chars)
      // so it never has to be stored; anything else looks like a missing page.
      const k = url.searchParams.get("k") ?? "";
      const expected = env.RT_SECRET ? (await hmac(env.RT_SECRET, "stats|v1")).slice(0, 24) : "";
      if (!expected || !safeEqual(expected, k)) return new Response("not found", { status: 404 });
      if (url.searchParams.get("view") !== "json") {
        return new Response(STATS_HTML, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
      }
      const q = new URLSearchParams();
      q.set("days", url.searchParams.get("days") ?? "2");
      return env.STATS.get(env.STATS.idFromName("registry")).fetch(`https://do/stats?${q}`);
    }
    if (url.pathname === "/selftest") return new Response(SELFTEST_HTML, { headers: { "content-type": "text/html; charset=utf-8" } });

    const m = url.pathname.match(/^\/room\/(.+)$/);
    if (!m) return new Response("not found", { status: 404 });
    const room = decodeURIComponent(m[1]);
    if (!ROOM_RE.test(room)) return new Response("bad room", { status: 400 });

    if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    const allowed = (env.ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const origin = req.headers.get("Origin") ?? "";
    if (allowed.length && origin && origin !== url.origin && !allowed.some((a) => origin === a || (a.startsWith("*.") && origin.endsWith(a.slice(1))))) {
      return new Response("origin not allowed", { status: 403 });
    }

    const role = (url.searchParams.get("role") ?? "viewer") as Role;
    if (!ROLES.includes(role)) return new Response("bad role", { status: 400 });
    const needsToken = role === "host" || (role === "control" && env.CONTROL_TOKEN_REQUIRED === "1");
    if (needsToken && !(await verifyToken(env.RT_SECRET, url.searchParams.get("token"), room, role))) {
      return new Response("unauthorized", { status: 401 });
    }

    const stub = env.ROOMS.get(env.ROOMS.idFromName(room));
    const fwd = new URL(req.url);
    fwd.searchParams.delete("token");
    return stub.fetch(new Request(fwd.toString(), req));
  },
} satisfies ExportedHandler<Env>;

// ───────────────────────────── Room ─────────────────────────────

export class Room implements DurableObject {
  private snapshot: string | null | undefined = undefined; // raw JSON payload text; undefined = not loaded yet
  private thumbs: Map<string, unknown> | undefined = undefined;
  private snapshotAt = 0;
  private presenceTimer: ReturnType<typeof setTimeout> | null = null;
  private lastPresenceSig = "";
  private lastHostPresent: boolean | undefined = undefined;
  private st: RoomStats | undefined = undefined; // today's usage counters (persisted by flushStats)
  private roomName = "";
  private reportTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private ctx: DurableObjectState, private env: Env) {
    // Answer keepalives without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/__ping") return new Response("ok");
    const role = (url.searchParams.get("role") ?? "viewer") as Role;
    const att: Attachment = { role, thumbs: url.searchParams.get("thumbs") === "1", at: Date.now() };
    try {
      await this.loadStats(decodeURIComponent(url.pathname.replace(/^\/room\//, "")));
      const st = this.touch();
      if (st) st.opened[role] = (st.opened[role] ?? 0) + 1;
    } catch {}

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [role]);
    server.serializeAttachment(att);

    const hasHost = this.sockets("host").length > 0;
    this.sendTo(server, "room:hello", { role, hasHost });
    if (role !== "host") await this.sendState(server, att);
    this.schedulePresence();
    this.reportSoon();

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    if (typeof raw !== "string") return;
    let msg: { e?: string; p?: unknown };
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    const e = msg.e;
    if (!e || typeof e !== "string") return;
    const att = ws.deserializeAttachment() as Attachment;
    try {
      if (!this.st) await this.loadStats();
      const st = this.touch();
      if (st) st.msgsIn++;
      this.reportSoon();
    } catch {}

    if (att.role === "host") {
      if (e === "snapshot") {
        const text = JSON.stringify(msg.p ?? null);
        this.snapshot = text;
        this.snapshotAt = Date.now();
        await this.ctx.storage.put({ snapshot: text, snapshotAt: this.snapshotAt });
        this.fanout(this.nonHost(), `{"e":"snapshot","p":${text}}`);
        return;
      }
      if (e === "thumbs") {
        await this.loadThumbs();
        const items = ((msg.p as { items?: { id: string; thumb: unknown }[] })?.items ?? []).filter((i) => i && typeof i.id === "string");
        for (const it of items) {
          this.thumbs!.set(it.id, it.thumb);
          await this.ctx.storage.put(`thumb:${it.id}`, it.thumb);
        }
        this.fanout(this.nonHost().filter((s) => (s.deserializeAttachment() as Attachment).thumbs), raw);
        return;
      }
      if (e === "room:reset") {
        // host cleared the session: drop stored state
        this.snapshot = null;
        this.thumbs = new Map();
        await this.ctx.storage.deleteAll();
        return;
      }
      this.fanout(this.nonHost(), raw);
      return;
    }

    // ── non-host senders ──
    if (e === "request") {
      await this.sendState(ws, att);
      return;
    }
    if (e.startsWith("display:")) {
      const targets = [...this.sockets("host"), ...this.sockets("control")];
      if (att.role === "control") targets.push(...this.sockets("display"), ...this.sockets("viewer"));
      this.fanout(targets.filter((s) => s !== ws), raw);
      return;
    }
    if (e === "command" && att.role !== "control") return; // only authenticated remotes may steer the host
    this.fanout(this.sockets("host"), raw);
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    try {
      ws.close(code === 1005 ? 1000 : code, "bye");
    } catch {}
    this.schedulePresence();
    try {
      if (!this.st) await this.loadStats();
      this.reportSoon();
    } catch {}
  }

  async webSocketError(): Promise<void> {
    this.schedulePresence();
  }

  // ── helpers ──

  private sockets(role: Role): WebSocket[] {
    return this.ctx.getWebSockets(role);
  }

  private nonHost(): WebSocket[] {
    return [...this.sockets("viewer"), ...this.sockets("display"), ...this.sockets("control")];
  }

  private fanout(targets: WebSocket[], frame: string): void {
    let sent = 0;
    for (const s of targets) {
      try {
        s.send(frame);
        sent++;
      } catch {}
    }
    if (sent) this.countOut(sent);
  }

  private sendTo(ws: WebSocket, e: string, p: unknown): void {
    try {
      ws.send(JSON.stringify({ e, p }));
      this.countOut(1);
    } catch {}
  }

  // ── usage counters (for /stats) ──

  private countOut(n: number): void {
    const st = this.touch();
    if (st) st.msgsOut += n;
  }

  /** Today's counters; rolls over at 00:00 UTC. */
  private touch(): RoomStats | undefined {
    const st = this.st;
    if (!st) return undefined;
    if (st.day !== utcDay()) Object.assign(st, freshStats());
    st.lastAt = Date.now();
    return st;
  }

  private async loadStats(name?: string): Promise<void> {
    if (name && !this.roomName) this.roomName = name;
    if (this.st) return;
    const [st, nm] = await Promise.all([
      this.ctx.storage.get<RoomStats>("stats"),
      this.ctx.storage.get<string>("roomName"),
    ]);
    if (!this.roomName && nm) this.roomName = nm;
    this.st = st && st.day === utcDay() ? st : freshStats();
  }

  /** At most one report per STATS_REPORT_MS while a room is active. Never affects the relay itself. */
  private reportSoon(): void {
    if (this.reportTimer || !isCountedRoom(this.roomName)) return;
    const ms = Number(this.env.STATS_REPORT_MS ?? 30_000) || 30_000;
    this.reportTimer = setTimeout(() => {
      this.reportTimer = null;
      void this.flushStats();
    }, ms);
  }

  private async flushStats(): Promise<void> {
    try {
      const st = this.st;
      if (!st || !isCountedRoom(this.roomName)) return;
      await this.ctx.storage.put({ stats: st, roomName: this.roomName });
      await this.env.STATS.get(this.env.STATS.idFromName("registry")).fetch("https://do/report", {
        method: "POST",
        body: JSON.stringify({ room: this.roomName, st }),
      });
    } catch {
      /* counters are best-effort */
    }
  }

  private async loadThumbs(): Promise<void> {
    if (this.thumbs) return;
    this.thumbs = new Map();
    const all = await this.ctx.storage.list({ prefix: "thumb:" });
    for (const [k, v] of all) this.thumbs.set(k.slice(6), v);
  }

  private async sendState(ws: WebSocket, att: Attachment): Promise<void> {
    if (this.snapshot === undefined) {
      this.snapshot = (await this.ctx.storage.get<string>("snapshot")) ?? null;
      this.snapshotAt = (await this.ctx.storage.get<number>("snapshotAt")) ?? 0;
    }
    // Never greet a new viewer with last week's captions: without a live host,
    // only replay state that is less than STALE_MS old.
    const fresh = this.sockets("host").length > 0 || Date.now() - this.snapshotAt < STALE_MS;
    if (this.snapshot && fresh) {
      try {
        ws.send(`{"e":"snapshot","p":${this.snapshot}}`);
        this.countOut(1);
      } catch {}
    }
    if (att.thumbs) {
      await this.loadThumbs();
      // batch under ~180 KB per frame, like the client did
      let batch: { id: string; thumb: unknown }[] = [];
      let size = 0;
      const flush = () => {
        if (batch.length) this.sendTo(ws, "thumbs", { items: batch });
        batch = [];
        size = 0;
      };
      for (const [id, thumb] of this.thumbs!) {
        const s = id.length + JSON.stringify(thumb).length + 32;
        if (size + s > 180_000) flush();
        batch.push({ id, thumb });
        size += s;
      }
      flush();
    }
  }

  private schedulePresence(): void {
    if (this.presenceTimer) return;
    this.presenceTimer = setTimeout(() => {
      this.presenceTimer = null;
      const counts = {
        host: this.sockets("host").length,
        viewers: this.sockets("viewer").length,
        displays: this.sockets("display").length,
        controls: this.sockets("control").length,
      };
      const st = this.touch();
      if (st) {
        st.peakViewers = Math.max(st.peakViewers, counts.viewers);
        st.peakSockets = Math.max(st.peakSockets, counts.viewers + counts.displays + counts.controls);
      }
      this.reportSoon();
      const hostPresent = counts.host > 0;
      if (hostPresent !== this.lastHostPresent) {
        // Lets viewers fall back to (or leave) the old path when the host is not on this relay.
        this.lastHostPresent = hostPresent;
        this.fanout(this.nonHost(), JSON.stringify({ e: "room:host", p: { present: hostPresent } }));
      }
      const sig = JSON.stringify(counts);
      if (sig === this.lastPresenceSig) return;
      this.lastPresenceSig = sig;
      const frame = JSON.stringify({ e: "room:presence", p: counts });
      this.fanout([...this.sockets("host"), ...this.sockets("control")], frame);
    }, PRESENCE_DEBOUNCE_MS);
  }
}

// ───────────────────────────── Registry (usage numbers for /stats) ─────────────────────────────
// One object. Rooms report their daily counters to it (at most once per STATS_REPORT_MS while active);
// /stats reads them back. Kept 21 days. A failure here can never affect a room.

export class Registry implements DurableObject {
  constructor(private ctx: DurableObjectState) {}

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "POST" && url.pathname === "/report") {
      const { room, st } = (await req.json()) as { room?: string; st?: RoomStats };
      if (!room || !st?.day) return new Response("bad", { status: 400 });
      await this.ctx.storage.put(`r:${st.day}:${room}`, st);
      await this.prune(st.day);
      return new Response("ok");
    }
    if (url.pathname === "/stats") {
      const days = Math.min(Math.max(Number(url.searchParams.get("days")) || 2, 1), 14);
      return Response.json(await this.report(days));
    }
    return new Response("not found", { status: 404 });
  }

  private async prune(today: string): Promise<void> {
    if ((await this.ctx.storage.get<string>("pruned")) === today) return;
    await this.ctx.storage.put("pruned", today);
    const cutoff = utcDay(Date.now() - STATS_KEEP_DAYS * 86_400_000);
    const old: string[] = [];
    for (const k of (await this.ctx.storage.list({ prefix: "r:" })).keys()) if (k.slice(2, 12) < cutoff) old.push(k);
    for (let i = 0; i < old.length; i += 128) await this.ctx.storage.delete(old.slice(i, i + 128));
  }

  private async report(days: number) {
    const iso = (t: number) => new Date(t).toISOString();
    const out: Record<string, unknown> = {};
    for (let i = 0; i < days; i++) {
      const day = utcDay(Date.now() - i * 86_400_000);
      const all = await this.ctx.storage.list<RoomStats>({ prefix: `r:${day}:` });
      const rooms = [...all.entries()].map(([k, st]) => ({ room: k.slice(13), st }));
      const byOwner: Record<string, { rooms: number; msgsIn: number; msgsOut: number; peakViewers: number; viewerSockets: number }> = {};
      const totals = { rooms: rooms.length, msgsIn: 0, msgsOut: 0, peakViewers: 0, peakSockets: 0 };
      for (const { room, st } of rooms) {
        totals.msgsIn += st.msgsIn;
        totals.msgsOut += st.msgsOut;
        totals.peakViewers = Math.max(totals.peakViewers, st.peakViewers);
        totals.peakSockets = Math.max(totals.peakSockets, st.peakSockets);
        const owner = room.split(":")[0];
        const o = (byOwner[owner] ??= { rooms: 0, msgsIn: 0, msgsOut: 0, peakViewers: 0, viewerSockets: 0 });
        o.rooms++;
        o.msgsIn += st.msgsIn;
        o.msgsOut += st.msgsOut;
        o.peakViewers = Math.max(o.peakViewers, st.peakViewers);
        o.viewerSockets += st.opened.viewer;
      }
      rooms.sort((a, b) => b.st.lastAt - a.st.lastAt);
      out[day] = {
        totals,
        byOwner,
        rooms: rooms.slice(0, 40).map(({ room, st }) => ({
          room,
          first: iso(st.firstAt),
          last: iso(st.lastAt),
          opened: st.opened,
          msgsIn: st.msgsIn,
          msgsOut: st.msgsOut,
          peakViewers: st.peakViewers,
          peakSockets: st.peakSockets,
        })),
      };
    }
    return { generatedAt: iso(Date.now()), note: "UTC days. msgsOut counts every frame delivered to a client.", days: out };
  }
}

// ───────────────────────────── usage page (/stats) ─────────────────────────────
// A readable view of the numbers; it loads the same URL with view=json. Add new accounts to LABELS below.
const STATS_HTML = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WORDaLIVE 사용 현황</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#6b7280;--card:#f5f6f8;--line:#e3e5e9;--ac:#1e6fd9}
@media(prefers-color-scheme:dark){:root{--bg:#141517;--fg:#ececec;--mut:#9aa0a6;--card:#1e2023;--line:#2e3135;--ac:#6aa8ff}}
body{font:14px/1.5 system-ui,-apple-system,sans-serif;margin:0;padding:16px;background:var(--bg);color:var(--fg);max-width:980px;margin-inline:auto}
h1{font-size:19px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 8px}.m{color:var(--mut);font-size:12px}
.nav a{color:var(--ac);margin-right:12px;text-decoration:none;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:8px 0}
.c{background:var(--card);border-radius:10px;padding:10px 12px}.c b{display:block;font-size:22px}.c span{color:var(--mut);font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
th:first-child,td:first-child{text-align:left}th{color:var(--mut);font-weight:600;font-size:12px}
.wrap{overflow-x:auto}
</style></head><body><h1>WORDaLIVE 사용 현황</h1>
<div class="m" id="gen">불러오는 중…</div>
<div class="nav" style="margin-top:6px"><a href="#" data-d="1">오늘</a><a href="#" data-d="2">2일</a><a href="#" data-d="7">7일</a></div>
<div id="out"></div>
<script>
var LABELS={'c5c00ea1':'관리자 (baehs)','56a22fad':'GRC (gracerivermedia)'};
var TZ='America/New_York';
function n(x){return Number(x||0).toLocaleString('ko-KR')}
function t(iso){return new Date(iso).toLocaleString('ko-KR',{timeZone:TZ,month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit',hour12:false})}
function who(id){var k=String(id).slice(0,8);return LABELS[k]||('계정 '+k)}
function esc(s){return String(s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
function card(v,l){return '<div class="c"><b>'+v+'</b><span>'+l+'</span></div>'}
function load(days){
  var u=new URL(location.href);u.searchParams.set('view','json');u.searchParams.set('days',days);
  fetch(u).then(function(r){return r.json()}).then(function(d){
    document.getElementById('gen').textContent='갱신 '+t(d.generatedAt)+' (미국 동부 시간) · 날짜 구분은 UTC 기준 · 배포 이후부터 집계';
    var h='';
    Object.keys(d.days).forEach(function(day){
      var x=d.days[day],tt=x.totals;
      h+='<h2>'+day+' (UTC)</h2><div class="cards">'+card(n(tt.rooms),'방(세션)')+card(n(tt.peakViewers),'최대 동시 휴대폰')+card(n(tt.msgsOut),'전달된 메시지')+card(n(tt.msgsIn),'받은 메시지')+'</div>';
      var o=Object.keys(x.byOwner);
      if(o.length){h+='<div class="wrap"><table><tr><th>계정</th><th>방</th><th>최대 휴대폰</th><th>받은</th><th>전달</th></tr>';
        o.forEach(function(k){var a=x.byOwner[k];h+='<tr><td>'+esc(who(k))+'</td><td>'+n(a.rooms)+'</td><td>'+n(a.peakViewers)+'</td><td>'+n(a.msgsIn)+'</td><td>'+n(a.msgsOut)+'</td></tr>'});h+='</table></div>'}
      if(x.rooms.length){h+='<div class="wrap"><table style="margin-top:10px"><tr><th>시작 → 마지막</th><th>계정</th><th>최대 휴대폰</th><th>최대 접속</th><th>전달</th></tr>';
        x.rooms.forEach(function(r){h+='<tr><td>'+t(r.first)+' → '+t(r.last)+'</td><td>'+esc(who(r.room))+'</td><td>'+n(r.peakViewers)+'</td><td>'+n(r.peakSockets)+'</td><td>'+n(r.msgsOut)+'</td></tr>'});h+='</table></div>'}
      else h+='<div class="m">이 날은 기록이 없습니다.</div>';
    });
    document.getElementById('out').innerHTML=h;
  }).catch(function(e){document.getElementById('gen').textContent='불러오지 못했습니다: '+e});
}
document.querySelectorAll('.nav a').forEach(function(a){a.onclick=function(e){e.preventDefault();load(a.dataset.d)}});
load(new URL(location.href).searchParams.get('days')||2);
<\/script></body></html>`;

// ───────────────────────────── live self-test page (/selftest) ─────────────────────────────
// Runs in the operator's browser against this deployment. The secret is typed in, never stored.
const SELFTEST_HTML = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relay Self-test</title><style>
body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:16px;background:#fff;color:#1a1a1a}
@media(prefers-color-scheme:dark){body{background:#151515;color:#eee}}
input,button{font:inherit;padding:8px;border-radius:6px;border:1px solid #8886;margin:4px 0}input{width:100%;box-sizing:border-box}
button{font-weight:600;cursor:pointer}.p{color:#1e8449}.f{color:#c0392b;font-weight:700}pre{white-space:pre-wrap}
</style></head><body><h2>WORDaLIVE 중계 서버 실전 점검</h2>
<label>RT_SECRET</label><input id="s" type="password" autocomplete="off">
<label>가상 휴대폰 수</label><input id="n" type="number" value="50">
<button id="go">점검 시작</button><pre id="out"></pre>
<script>
const out=document.getElementById("out");const log=(ok,t)=>{out.innerHTML+='<span class="'+(ok?'p':'f')+'">'+(ok?'PASS':'FAIL')+'</span>  '+t+'\\n'};
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
async function tok(sec,room,role){const exp=Math.floor(Date.now()/1000)+3600;const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(sec),{name:'HMAC',hash:'SHA-256'},false,['sign']);return exp+'.'+b64u(await crypto.subtle.sign('HMAC',k,new TextEncoder().encode(room+'|'+role+'|'+exp)))}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function open(room,role,q={}){const u=new URL('/room/'+encodeURIComponent(room),location.href);u.protocol=location.protocol==='https:'?'wss:':'ws:';u.searchParams.set('role',role);for(const[k,v]of Object.entries(q))u.searchParams.set(k,v);
const ws=new WebSocket(u);const c={ws,got:{},last:{}};ws.onmessage=e=>{if(e.data==='pong'){c.got.pong=(c.got.pong||0)+1;return}const m=JSON.parse(e.data);c.got[m.e]=(c.got[m.e]||0)+1;c.last[m.e]=m.p;c.onm&&c.onm(m)};
c.ready=new Promise(r=>{ws.onopen=()=>r(true);ws.onerror=()=>r(false)});return c}
const send=(c,e,p)=>c.ws.send(JSON.stringify({e,p}));
document.getElementById('go').onclick=async()=>{out.textContent='';const sec=document.getElementById('s').value.trim();const N=+document.getElementById('n').value||50;const room='selftest-'+Date.now()+':s';
const bad=open(room,'host',{token:'1.x'});log(!(await bad.ready),'토큰 없는 호스트 차단');
const host=open(room,'host',{token:await tok(sec,room,'host')});const hok=await host.ready;log(hok,'호스트 접속 (RT_SECRET 일치)');if(!hok){log(false,'RT_SECRET 값이 Cloudflare 설정과 다릅니다');return}
const ctl=open(room,'control',{token:await tok(sec,room,'control'),thumbs:'1'});const vs=Array.from({length:N},()=>open(room,'viewer'));
const ok=(await Promise.all([ctl.ready,...vs.map(v=>v.ready)])).filter(Boolean).length;log(ok===N+1,'구독자 접속 '+ok+'/'+(N+1));await sleep(2500);
log(host.last['room:presence']?.viewers===N,'접속자 수 집계: '+JSON.stringify(host.last['room:presence']));
const lat=[];for(const v of vs)v.onm=m=>{if(m.e==='snapshot'&&m.p.t)lat.push(performance.now()-m.p.t)};
const lines=Array.from({length:30},(_,i)=>({id:'l'+i,source:'가'.repeat(60),translated:'word '.repeat(40)}));
for(let i=0;i<40;i++){send(host,'snapshot',{seq:i,t:performance.now(),lines});await sleep(500)}await sleep(1500);
lat.sort((a,b)=>a-b);const q=x=>Math.round(lat[Math.min(lat.length-1,Math.floor(x*lat.length))]);
log(lat.length===N*40,'자막 '+(N*40)+'건 중 '+lat.length+'건 도착 · 보통 '+q(.5)+'ms · 느린쪽(95%) '+q(.95)+'ms · 최대 '+Math.round(lat.at(-1))+'ms');
const late=open(room,'viewer');await late.ready;await sleep(600);log(late.last.snapshot?.seq===39,'늦게 들어온 휴대폰이 최신 자막 즉시 수신');
send(late,'request',{});await sleep(600);log(!host.got.request&&vs[0].got.snapshot===40,'재요청은 요청자에게만 (호스트·다른 폰 영향 없음)');
send(vs[0],'display:heartbeat',{id:'p'});send(vs[1],'command',{type:'x'});send(ctl,'command',{type:'next'});await sleep(600);
log(host.got['display:heartbeat']===1&&!vs[2].got['display:heartbeat'],'heartbeat 는 호스트에게만');
log(host.got.command===1&&host.last.command?.type==='next','리모컨 명령만 호스트에 전달, 일반 폰 명령은 차단');
vs[3].ws.send('ping');await sleep(500);log(vs[3].got.pong===1,'ping→pong 자동응답');
for(const c of [host,ctl,late,...vs])c.ws.close();out.innerHTML+='\\n끝. 이 화면을 캡처해 보내 주세요.'};
</script></body></html>`;
