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

    const m = url.pathname.match(/^\/room\/(.+)$/);
    if (!m) return new Response("not found", { status: 404 });
    const room = decodeURIComponent(m[1]);
    if (!ROOM_RE.test(room)) return new Response("bad room", { status: 400 });

    if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    const allowed = (env.ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const origin = req.headers.get("Origin") ?? "";
    if (allowed.length && origin && !allowed.some((a) => origin === a || (a.startsWith("*.") && origin.endsWith(a.slice(1))))) {
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
