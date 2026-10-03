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
 *
 * Keepalive: clients send the literal text "ping"; the room auto-replies "pong"
 * without waking (hibernation-friendly, not billed as a message).
 */

export interface Env {
  ROOMS: DurableObjectNamespace;
  RT_SECRET: string; // shared with the Lovable server function that mints host/control tokens
  ALLOWED_ORIGINS?: string; // comma-separated; empty = allow all
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
    if ((role === "host" || role === "control") && !(await verifyToken(env.RT_SECRET, url.searchParams.get("token"), room, role))) {
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
  private presenceTimer: ReturnType<typeof setTimeout> | null = null;
  private lastPresenceSig = "";

  constructor(private ctx: DurableObjectState, private env: Env) {
    // Answer keepalives without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/__ping") return new Response("ok");
    const role = (url.searchParams.get("role") ?? "viewer") as Role;
    const att: Attachment = { role, thumbs: url.searchParams.get("thumbs") === "1", at: Date.now() };

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [role]);
    server.serializeAttachment(att);

    const hasHost = this.sockets("host").length > 0;
    this.sendTo(server, "room:hello", { role, hasHost });
    if (role !== "host") await this.sendState(server, att);
    this.schedulePresence();

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

    if (att.role === "host") {
      if (e === "snapshot") {
        const text = JSON.stringify(msg.p ?? null);
        this.snapshot = text;
        await this.ctx.storage.put("snapshot", text);
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
    for (const s of targets) {
      try {
        s.send(frame);
      } catch {}
    }
  }

  private sendTo(ws: WebSocket, e: string, p: unknown): void {
    try {
      ws.send(JSON.stringify({ e, p }));
    } catch {}
  }

  private async loadThumbs(): Promise<void> {
    if (this.thumbs) return;
    this.thumbs = new Map();
    const all = await this.ctx.storage.list({ prefix: "thumb:" });
    for (const [k, v] of all) this.thumbs.set(k.slice(6), v);
  }

  private async sendState(ws: WebSocket, att: Attachment): Promise<void> {
    if (this.snapshot === undefined) this.snapshot = (await this.ctx.storage.get<string>("snapshot")) ?? null;
    if (this.snapshot) {
      try {
        ws.send(`{"e":"snapshot","p":${this.snapshot}}`);
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
      const sig = JSON.stringify(counts);
      if (sig === this.lastPresenceSig) return;
      this.lastPresenceSig = sig;
      const frame = JSON.stringify({ e: "room:presence", p: counts });
      this.fanout([...this.sockets("host"), ...this.sockets("control")], frame);
    }, PRESENCE_DEBOUNCE_MS);
  }
}

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
