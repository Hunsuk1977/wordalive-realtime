# wordalive-realtime

WORDaLIVE 실시간 자막 중계 서버 (Cloudflare Worker + Durable Object).
Supabase broadcast 채널 `prompter:${ownerId}:${sessionId}` 하나 = 방(Room) 하나.

## 접속
```
wss://<worker>/room/<ownerId>:<sessionId>?role=host|viewer|display|control[&token=...][&thumbs=1]
```
- host, control: 토큰 필수 — `${exp}.${base64url(HMAC_SHA256(RT_SECRET, "${room}|${role}|${exp}"))}`
- viewer, display: 토큰 없음 (읽기 전용)
- 프레임: `{"e": 이벤트, "p": 페이로드}` — 이벤트 이름은 기존 Supabase broadcast 와 동일
- keepalive: 텍스트 `ping` → `pong` (방을 깨우지 않음)

## 라우팅
| 보낸 쪽 | 이벤트 | 받는 쪽 |
|---|---|---|
| host | snapshot | 저장 + 호스트 외 전원 |
| host | thumbs | 저장 + `thumbs=1` 소켓만 |
| host | 그 외 (display:tts 등) | 호스트 외 전원 |
| 그 외 | request | 방이 직접, 요청자에게만 응답 |
| control | command | 호스트만 |
| viewer/display | command | 버림 |
| 그 외 | display:* | 호스트 + 리모컨 (리모컨이 보낸 것은 디스플레이에도) |
| 방 | room:hello | 접속 시 `{role, hasHost}` |
| 방 | room:presence | 접속자 수가 바뀔 때 호스트 + 리모컨에게 |

## 배포 (최초 1회)
1. Cloudflare 대시보드 → Workers & Pages → Create → Import a repository → 이 저장소 선택 → Deploy
2. 배포된 Worker → Settings → Variables and Secrets → Add → Type: Secret, Name: `RT_SECRET`, Value: (Lovable 에 넣는 값과 동일)
3. 이후에는 main 브랜치에 push 하면 자동 배포

## 로컬 테스트
```
echo 'RT_SECRET="test-secret-123"' > .dev.vars
npx wrangler dev --port 8787
node test/load.mjs            # VIEWERS=200 node test/load.mjs
```

## Usage numbers (`/stats`)

Every room counts the frames it receives and delivers, the most phones connected at once, and how many sockets opened per role.
It reports to one `Registry` object (at most once per `STATS_REPORT_MS`, default 30 s, while a room is active). Kept 21 days.

`GET /stats?k=<key>&days=2` — `key` is the first 24 characters of `base64url(HMAC_SHA256(RT_SECRET, "stats|v1"))`.
Without the key the path answers 404. Days are UTC. `/selftest` and `/diag` rooms are not counted.
Counters are best-effort and can never affect a room (all reporting is wrapped in try/catch).

Deploying this version adds migration `v2` (new Durable Object class `Registry`); `npx wrangler deploy` applies it.
