# Argus Web Control-Plane — Implementation Plan (Plan 2 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. REQUIRED before each task: read `CLAUDE.md` + invoke **argus-architect**. Frontend tasks additionally require the **dataviz** skill before chart code.
>
> **Rev 2** — hardened after two independent adversarial reviews (security + coverage). Changelog at end. The three security BLOCKINGs (public bind, version/audit divergence, DNS-rebinding) and the dropped close-the-loop UI are all fixed here.

**Goal:** Add the local observability + governance UI on the Plan-1 engine: `argus serve` (localhost web app — live tail, stats, explain, policy editor, **replay simulator**, and **close-the-loop allow/downgrade from a decision row**) + `argus replay` CLI.

**Architecture:** `net/http` server bound to loopback only, serving a JSON+SSE API and a **no-build** static frontend embedded via `//go:embed`. The moat is a pure **replay engine** that re-scores stored decisions against a candidate policy. The Plan-1 verdict path is untouched; this plane reads the DB and, for the editor/close-the-loop, validates-then-writes `policy.json` + a version snapshot. The server is authenticated only by being loopback-bound, so it defends the two browser-reachable attack vectors explicitly: **Host-header allowlist** (defeats DNS-rebinding) and **CSRF protection on mutating routes**.

**Tech Stack:** Go 1.26 · stdlib `net/http`, `embed`, `encoding/json`, `net` · reuse `internal/{store,policy,classify,verdict,hook,shellast}` · **frontend: no npm/node/vite/framework** — hand-written HTML/CSS + per-tab ES modules, optionally a single vendored ~4 KB Preact+htm ESM file (embedded, no build). Inline SVG charts per dataviz.

## Global Constraints

- Module `github.com/lucasngucii/argus`. Go **1.26**. **`CGO_ENABLED=0`**, and **no JS build toolchain** (no `package.json`/`node_modules`) — frontend is static files embedded with `//go:embed`, one `go build` builds everything.
- **Loopback-only, enforced for real.** Default `--addr 127.0.0.1:4600`. Reject any bind whose host is empty, `0.0.0.0`, `::`, or any non-loopback address; a port-only addr (`:4600`) is rewritten to `127.0.0.1:4600`, never left as the wildcard. Only `127.0.0.1` / `::1` / `localhost` hosts are allowed.
- **Browser-attack defense (both required):** (1) a **Host-header allowlist** middleware on ALL routes — reject unless `Host` is `127.0.0.1:<port>` / `localhost:<port>` / `[::1]:<port>` (defeats DNS-rebinding, which keeps the attacker's Host). (2) **CSRF** on mutating routes (`PUT/POST`): require header `X-Argus-CSRF: 1` (a custom header browsers can't set cross-origin without a preflight) AND `Content-Type: application/json`; reject otherwise.
- **Policy version = the document's own `version` field, single source of truth.** Plan-1 writes `decisions.policy_version = pol.Version` and `init` stamps `InsertPolicyVersion(1, …)` to match `Default().Version==1`. Any policy write here MUST set the document's `version = maxExistingVersion+1`, write that into `policy.json`, and record `InsertPolicyVersion(thatSameVersion, …)` — so a decision's `policy_version` always resolves to a snapshot and `replay --version N` lines up. Never key snapshots off an independent counter.
- **Read-mostly; validate-before-write.** Mutating endpoints (`PUT /api/policy`, `POST /api/allowlist`) MUST `policy.Validate` the resulting policy against the schema BEFORE touching `policy.json`; on invalid, return 400 and leave the file unchanged.
- **Engine is authoritative & reused, never reimplemented.** Stats/explain/replay/close-the-loop call `classify.Classify` / `verdict.Map` / `policy.*`. No parallel classification.
- **Replay is pure & read-only**; reconstructs `hook.Payload` from a `store.Row`; never writes decisions or `policy.json`.
- **`store` gains `Close()`** (parked Plan-1 finding) and `serve` calls it on shutdown; shutdown is bounded and must not hang on an open SSE connection.
- All request bodies wrapped in `http.MaxBytesReader` (1 MB).
- Commit identity `lucasngucii <lucasalehwork@gmail.com>`; **never** a `Co-Authored-By: Claude` trailer.

## Consumes from Plan 1 (exact signatures — do not guess)

```go
// internal/hook
type ToolInput struct{ Command, FilePath string } // json: command, file_path
type Payload struct{ SessionID, TranscriptPath, CWD, PermissionMode, HookEventName, ToolName, ToolUseID string; ToolInput ToolInput }
func (p Payload) Subject() string // Command if ToolName=="Bash" else FilePath

// internal/classify
type Decision struct{ Severity, RuleID, Reason string; Obfuscated bool } // NOTE: singular Reason + Obfuscated (bool) — use these names, not "reasons"/"obfuscation"
func Classify(p hook.Payload, pol policy.Policy) Decision

// internal/verdict
func Map(severity, permissionMode string) string // allow|ask|deny

// internal/policy
type Policy struct{ Version int; Meta map[string]string; Defaults Defaults; Rules []Rule }
type Rule struct{ ID string; Enabled, AlwaysHigh, Allow bool; Tool []string; Match Match; Severity, Reason string; ContextEscalation []Escalation }
func Load(path string) (Policy, error) // reads+schema-validates+unmarshals
func Default() Policy

// internal/store (Plan-1 surface; Task 1 EXTENDS it)
type Row struct{ TS, Session, CWD, Tool, Command, File, Severity, Verdict, PermissionMode, RuleID, Harness string; PolicyVersion int; Obfuscation bool }
func Open(path string) (*Store, error)
func (s *Store) Insert(r Row) error
func (s *Store) Recent(limit int) ([]Row, error)          // newest-first
func (s *Store) Counts() (map[string]int, error)          // full-history GROUP BY severity
func (s *Store) InsertPolicyVersion(version int, author, note, policyJSON, hash string) error
func (s *Store) PolicyVersionCount() (int, error)
```
Legacy note: `init` imports old `agent-review` rows with `Harness:"agent-review"`, `RuleID:"legacy-import"`, scored by the OLD engine — replay must exclude these (see Task 3).

## File Structure

```
internal/store/store.go            # +Close, +Row.ID(+json tags), +DecisionsAfter, +Page, +MaxID,
                                    #   +DistinctSessions(WHERE session!=''), +VerdictCount,
                                    #   +PolicyVersions/+PolicyVersionJSON, +AllDecisions(cap, claudeCodeOnly)
internal/policy/validate.go        # +Validate([]byte) error, +SeedRuleIDs() []string
internal/replay/replay.go          # pure Rescore + diff, MaxReplay const
internal/web/server.go             # http.Server, loopback-bind validation, graceful shutdown
internal/web/middleware.go         # Host-allowlist + CSRF + MaxBytesReader
internal/web/handlers.go           # /api/* handlers; per-request policy load
internal/web/sse.go                # per-connection SSE poll loop (no hub)
internal/web/static/index.html     # embedded shell (no build)
internal/web/static/*.js           # per-tab ES modules (+ optional vendored preact-htm.mjs)
internal/web/static/style.css      # theme-aware
internal/web/embed.go              # //go:embed static/*
internal/cli/{serve,replay}.go
internal/cli/doctor.go             # MODIFY: seed-rule WARN
cmd/argus/main.go                  # wire serve, replay
```

---

### Task 1: Store read-surface + `Close()` + `Row.ID`

**Files:** Modify `internal/store/store.go`, `store_test.go`
**Produces:**
- `func (s *Store) Close() error`.
- `Row` gains `ID int` as first field, and **all `Row` fields get json tags** (`id,ts,session,cwd,tool,command,file,severity,verdict,permission_mode,rule_id,harness,policy_version,obfuscation`) so API/JSONL output has stable snake_case keys. `Recent` selects/scans `id`.
- `func (s *Store) MaxID() (int, error)` — `SELECT COALESCE(MAX(id),0)`.
- `func (s *Store) DecisionsAfter(afterID, limit int) ([]Row, error)` — `id>afterID`, oldest-first.
- `func (s *Store) Page(severity string, limit, beforeID int) ([]Row, error)` — newest-first; empty severity = all; `beforeID<=0` = newest.
- `func (s *Store) DistinctSessions() (int, error)` — `COUNT(DISTINCT session) WHERE session != ''` (match `stats.go`'s CLI behavior — do NOT count the empty session).
- `func (s *Store) VerdictCount(verdict string) (int, error)` — full-history count.
- `type VersionMeta struct{ Version int; TS, Author, Note, Hash string }`; `PolicyVersions() ([]VersionMeta, error)` (newest-first); `PolicyVersionJSON(version int) (string, error)`.
- `func (s *Store) AllDecisions(cap int, claudeCodeOnly bool) (rows []Row, capped bool, err error)` — oldest-first up to `cap`; when `claudeCodeOnly`, `WHERE harness='claude-code'` (excludes legacy-import rows); `capped=true` when truncated.

- [ ] **Step 1: Failing tests** — cover `Close`, cursor (`DecisionsAfter` returns rows with real ids; a mid cursor returns the tail), `Page("high",…)` filter, `DistinctSessions` ignores `''` (insert one row with `Session:""` and one with `Session:"s1"` → count 1), `VerdictCount("deny")`, `PolicyVersions`/`PolicyVersionJSON` round-trip, `AllDecisions(3,false)` capped, and `AllDecisions(100,true)` excludes a `Harness:"agent-review"` row.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement.** Add `ID` + json tags; update `Recent`'s SELECT/Scan to include `id`. **Cross-task ripples to fix in THIS step:** (a) `store_test.go` `TestRecentRoundTrip` compares whole `Row` structs at THREE sites (`got[0]`, `got[1]`, and the `all[i]` loop) — zero `ID` on each before comparing, or assert ids separately. (b) `internal/cli/stats.go` `--jsonl` marshals `Row`; with json tags it now emits `"id"` and snake_case keys — update `TestStats_JSONL` if it asserts Go-cased field names (it asserts `Severity`/`TS` — switch to `severity`/`ts`). Run full `go test ./...` to catch any other consumer.
- [ ] **Step 4: Run → PASS** (full suite green).
- [ ] **Step 5: Commit** `feat(store): Close, Row.ID+json tags, cursor/page/version/verdict/all read methods`.

---

### Task 2: `policy.Validate` + `policy.SeedRuleIDs`

**Files:** Create `internal/policy/validate.go`, `internal/policy/validate_test.go`
**Produces:**
- `func Validate(b []byte) error` — schema-validate raw policy JSON (refactor the existing schema-validate path out of `Load` so both `Load(path)` and `Validate(bytes)` share it; `Load` becomes read-file → `Validate` → unmarshal). Returns the schema error on invalid.
- `func SeedRuleIDs() []string` — the baseline rule IDs from `Default()` (`rm-recursive, git-danger, sudo, docker-service, db-write, opaque-exec`), derived from `Default().Rules` (not hard-coded) so it can't drift.

- [ ] **Step 1: Failing tests** — `Validate([]byte(`{"version":"x"}`))` errors; `Validate` of `Default()` marshaled is nil; `SeedRuleIDs()` contains `sudo` and equals the non-alwaysHigh rule IDs of `Default()`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**; ensure `Load` still passes its Plan-1 tests after the refactor (run `go test ./internal/policy/...`).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(policy): Validate(bytes) + SeedRuleIDs helpers (shared schema-validate path)`.

---

### Task 3: Replay engine (the moat) — pure re-score + diff

**Files:** Create `internal/replay/replay.go`, `replay_test.go`
**Produces:**
- `const MaxReplay = 50000`.
- `type Change struct{ Row store.Row; OldSeverity, NewSeverity, OldVerdict, NewVerdict string }`
- `type Result struct{ Total int; Changed []Change; Summary map[string]int; Capped bool }`
- `func Rescore(rows []store.Row, capped bool, candidate policy.Policy) Result` — pure. For each row build `hook.Payload{ToolName:r.Tool, PermissionMode:r.PermissionMode, CWD:r.CWD, ToolInput:hook.ToolInput{Command:r.Command, FilePath:r.File}}`; `new := classify.Classify(payload, candidate)`; `nv := verdict.Map(new.Severity, r.PermissionMode)`; compare to stored `r.Severity`/`r.Verdict`; collect only changed rows; `Summary["<oldVerdict>-><newVerdict>"]++`.

**Scope note (from review A4):** replay re-scores the **logged** history. Plan-1's gate does NOT persist `safe` decisions (noise reduction), so replay covers `low`/`medium`/`high` rows — it shows transitions like `low→medium` ("previously allowed, now flagged"), but cannot resurface a command that was `safe`+unlogged. Document this in the CLI/UI output. Test fixtures therefore use **reachable** rows (`low`/`medium`/`high`, never `safe`).

- [ ] **Step 1: Failing tests** (use reachable fixtures):
```go
// a low/allow row that a stricter candidate escalates to medium
func TestRescoreEscalation(t *testing.T) {
  rows := []store.Row{{Tool:"Bash", Command:"rm -rf ./buildcache", PermissionMode:"default", Severity:"low", Verdict:"allow"}}
  // candidate: a policy whose rm rule scores this medium (or default() where cwd-context escalates) — pick one that changes it
  res := replay.Rescore(rows, false, strictCandidate())
  if len(res.Changed) != 1 || res.Changed[0].NewVerdict != "ask" { t.Fatalf("%+v", res.Changed) }
  if res.Summary["allow->ask"] != 1 { t.Fatalf("summary %+v", res.Summary) }
}
func TestRescoreUnchangedNotReported(t *testing.T) {
  rows := []store.Row{{Tool:"Bash", Command:"sudo apt-get update", PermissionMode:"default", Severity:"medium", Verdict:"ask"}}
  if len(replay.Rescore(rows, false, policy.Default()).Changed) != 0 { t.Fatal("unchanged must not appear") }
}
func TestRescorePropagatesCapped(t *testing.T){ if !replay.Rescore(nil, true, policy.Default()).Capped { t.Fatal("capped") } }
```
(Provide `strictCandidate()` as a small policy in the test that deterministically changes the fixture — e.g. an `Allow`-less policy plus a rule that makes `rm -rf ./buildcache` medium, OR reuse `Default()` with the row's `CWD` set to a prod path so context-escalation fires. Choose whichever is deterministic against the real classifier.)
- [ ] **Step 2: Run → FAIL.**  — [ ] **Step 3: Implement.**  — [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(replay): pure re-score/diff over logged (low+) history`.

---

### Task 4: `argus replay` CLI

**Files:** Create `internal/cli/replay.go`, `replay_test.go`; Modify `cmd/argus/main.go`
**Produces:** `func Replay(s *store.Store, candidate policy.Policy, w io.Writer) int` — `rows, capped, _ := s.AllDecisions(replay.MaxReplay, true)` (claude-code only), `replay.Rescore`, print `N decisions scored, M changed`, the transition table, each changed row `old→new`, and if `capped` a `NOTE: only first 50000 scored`, plus a one-line `NOTE: safe (unlogged) decisions are not covered`.

- [ ] **Step 1: Failing test** — seed a `low/allow` row that the candidate escalates; assert output has `1 changed` and the transition.
- [ ] **Step 2–4:** wire `case "replay"` in main.go (`--policy FILE` default current `~/.argus/policy.json`, or `--version N` via `PolicyVersionJSON`). PASS.
- [ ] **Step 5: Commit** `feat(cli): argus replay`.

---

### Task 5: HTTP server scaffold — loopback bind + graceful shutdown + embedded static

**Files:** Create `internal/web/server.go`, `internal/web/embed.go`, `internal/web/static/index.html` (placeholder), `server_test.go`
**Produces:**
- `//go:embed static/*` → `staticFS embed.FS`.
- `func New(s *store.Store, policyPath, addr string) (*Server, error)` — validates `addr`: parse with `net.SplitHostPort`; empty/`0.0.0.0`/`::`/non-loopback host → error; port-only → rewrite host to `127.0.0.1`. Store the normalized addr.
- `func (srv *Server) Handler() http.Handler` — mux wrapped in the middleware chain (Task 6). `GET /`, `GET /static/*` from `staticFS`; unknown `/api/*` → 404 JSON.
- `func (srv *Server) ListenAndServe(ctx context.Context) error` — serve; on `ctx.Done()`, `Shutdown` with a **bounded 5 s context**; also signal the SSE loops to stop (a `srv.shutdown chan struct{}` closed here — Task 8 selects on it) so an open SSE connection can't block shutdown.

- [ ] **Step 1: Failing tests** — `New(...,"127.0.0.1:4600")` ok; `New(...,":4600")` normalizes host to `127.0.0.1` (assert via an exported normalized-addr getter or by binding `:0` and checking `Addr()`); `New(...,"0.0.0.0:4600")` and `New(...,":4600")`-as-wildcard errors; `New(...,"1.2.3.4:80")` errors. `Handler()` serves `/` (200, contains `<`) and returns JSON 404 for `/api/nope`.
- [ ] **Step 2–4:** implement; index.html one-line placeholder (real UI Tasks 12a–c). PASS.
- [ ] **Step 5: Commit** `feat(web): server scaffold — loopback-only bind, embedded static, bounded graceful shutdown`.

---

### Task 6: Security middleware — Host allowlist + CSRF + body limit

**Files:** Create `internal/web/middleware.go`, `middleware_test.go`; wire into `Handler()`
**Produces:**
- `hostGuard(next)` — reject (403 JSON) unless `r.Host` ∈ {`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`} for the server's port. Applied to ALL routes (defeats DNS-rebinding).
- `csrfGuard(next)` — for `PUT`/`POST`/`DELETE`: require `X-Argus-CSRF: 1` header AND `Content-Type: application/json`; else 403. GET/HEAD pass.
- `limitBody(next)` — wrap `r.Body` in `http.MaxBytesReader(w, r.Body, 1<<20)`.

- [ ] **Step 1: Failing tests** — a `GET /` with `Host: evil.com` → 403; with `Host: 127.0.0.1:4600` → 200. `PUT /api/policy` without `X-Argus-CSRF` → 403; with it + `application/json` → passes the guard (reaches handler). A `POST` with `Content-Type: text/plain` → 403.
- [ ] **Step 2–4:** implement; chain order `hostGuard → csrfGuard → limitBody → mux`. PASS.
- [ ] **Step 5: Commit** `feat(web): Host-allowlist (anti DNS-rebinding) + CSRF + body-limit middleware`.

---

### Task 7: `GET /api/stats`

**Files:** `internal/web/handlers.go`, `handlers_test.go`
**Produces:** `GET /api/stats` → `{counts:{sev:n}, deny:n, sessions:n, recent:[Row…]}` via `store.Counts`, `store.VerdictCount("deny")`, `store.DistinctSessions`, `store.Page("",50,0)` (use `Page`, not a second `Recent` call site). Per-project heatmap + trend are **explicitly descoped to a later iteration** (documented here — keep v1 lean; not silently dropped).

- [ ] **Step 1: Failing test** — 1 high/deny + 2 low/allow → `counts.high==1`, `counts.low==2`, `deny>=1`, decodes cleanly.
- [ ] **Step 2–4:** PASS. — [ ] **Step 5: Commit** `feat(web): GET /api/stats`.

---

### Task 8: `GET /api/decisions` + `GET /api/stream` (SSE poll loop, no hub)

**Files:** Modify `handlers.go`; Create `internal/web/sse.go`, `sse_test.go`
**Produces:**
- `GET /api/decisions?severity=&limit=&before=` → `{rows:[…], nextBefore:id}` via `store.Page`; `limit` clamped `[1,200]` default 50.
- `GET /api/stream` — **one poll loop per connection, no pub/sub hub.** Set `text/event-stream`; seed cursor from `store.MaxID()`; on a ticker (interval a `New`-time field, default 1 s), `store.DecisionsAfter(cursor,100)`, emit each as `data: <json>\n\n`, advance cursor, `flusher.Flush()`. `defer ticker.Stop()`. Return promptly when EITHER the request context is done (client disconnect) OR `srv.shutdown` is closed (server shutdown). If `DecisionsAfter` returns "database is closed" (shutdown race), log-and-return — never panic. 500 if `w` is not an `http.Flusher`.

- [ ] **Step 1: Failing tests** — `/api/decisions?severity=low` filter + `?limit=1` pagination. SSE: with a small interval, start the handler on an `httptest` server, `Insert` a row, read one `data:` line containing its severity (bounded-timeout read so it can't hang), then cancel the context and assert the handler returns; separately assert closing `srv.shutdown` also makes it return.
- [ ] **Step 2–4:** implement. PASS.
- [ ] **Step 5: Commit** `feat(web): GET /api/decisions + GET /api/stream (per-connection SSE, shutdown-aware)`.

---

### Task 9: `POST /api/explain`

**Files:** `handlers.go`, `handlers_test.go`
**Produces:** `POST /api/explain` body `{command,tool,cwd,mode,file}` → `{severity,ruleId,reason,verdict,obfuscated,commands:[…],pipeSinks:[…]}`. Build `hook.Payload` (include `ToolInput.FilePath` from `file` so Write/Edit decisions explain correctly, not just Bash), **load the policy per-request from `policyPath`** (always current after an edit — no cached-staleness, no lock), run `classify.Classify` + `verdict.Map` + `shellast.Extract`.

- [ ] **Step 1: Failing tests** — `{"command":"sudo rm -rf /","tool":"Bash","mode":"default"}` → severity high, verdict deny, non-empty ruleId. `{"file":"/x/.ssh/id_ed25519","tool":"Write","mode":"default"}` → high/deny (proves `file` wired).
- [ ] **Step 2–4:** PASS. — [ ] **Step 5: Commit** `feat(web): POST /api/explain (Bash + Write/Edit)`.

---

### Task 10: `GET/PUT /api/policy` + versions (document-version audit, validate-before-write)

**Files:** `handlers.go`, `handlers_test.go`
**Produces:**
- `GET /api/policy` → `{json:<current policy.json text>, versions:[VersionMeta…]}`.
- `GET /api/policy/versions/{v}` → that snapshot's JSON (`store.PolicyVersionJSON`).
- `PUT /api/policy` body = candidate policy JSON: `policy.Validate(body)` FIRST → on invalid `400` + **file untouched**; on valid, compute `next := maxVersion+1` from `store.PolicyVersions()`, **set the document's `version` field to `next`** (re-marshal), write `policy.json`, `store.InsertPolicyVersion(next,"web",note,json,sha256)`, return `{version:next}`. This keeps `decisions.policy_version` (gate writes `pol.Version`) resolvable to a snapshot (fixes the audit-divergence BLOCKING).

- [ ] **Step 1: Failing tests** — invalid body (`{"version":"x"}`) → 400 AND on-disk file byte-identical to before; valid minimal policy → 200, on-disk `version` now `maxVersion+1`, a matching `policy_versions` row exists with the SAME version number; `GET /api/policy` returns updated json + versions list; `GET /api/policy/versions/{that}` returns it.
- [ ] **Step 2–4:** implement (goes through the Task 6 CSRF/Host guards). PASS.
- [ ] **Step 5: Commit** `feat(web): GET/PUT /api/policy + versions (document-version audit, validate-before-write)`.

---

### Task 11: `POST /api/replay` + `POST /api/allowlist` (close-the-loop)

**Files:** `handlers.go`, `handlers_test.go`
**Produces:**
- `POST /api/replay` body = candidate policy JSON → `policy.Validate` → `store.AllDecisions(replay.MaxReplay,true)` → `replay.Rescore` → `{total,changed:[…],summary:{…},capped}`.
- `POST /api/allowlist` (the dropped close-the-loop, spec §6/§9) body `{command, tool, note}` → build an `Allow:true` rule that matches that command's shape (e.g. `Match.Cmd` = the resolved first command name via `shellast.Extract`, plus a tightening `Match.ArgMatches` from a stable substring of the command, or `Match.Raw` of the exact command — keep it as specific as practical), append it to the current policy, then go through the SAME validate → set version → write → snapshot path as PUT. **The always-high floor still wins** (allow rules can't downgrade a floor/`AlwaysHigh` hit — that's enforced by `classify.Classify`, so this endpoint doesn't need special-casing, but a test must prove a floor command stays denied after an allowlist attempt).

- [ ] **Step 1: Failing tests** — `POST /api/replay` with `Default()` over a seeded escalatable `low/allow` row → a transition present, `total>=1`. `POST /api/allowlist {"command":"sudo apt-get update","tool":"Bash"}` → 200, a new version written, and afterward `POST /api/explain` of `sudo apt-get update` → allow/safe; BUT `POST /api/allowlist {"command":"sudo rm -rf /"}` then explain of `sudo rm -rf /` → STILL deny (floor non-downgradable).
- [ ] **Step 2–4:** implement (CSRF/Host guarded). PASS.
- [ ] **Step 5: Commit** `feat(web): POST /api/replay + POST /api/allowlist (close-the-loop, floor-capped)`.

---

### Task 12a: Frontend shell + Live + Stats

**Files:** Replace `static/index.html`; create `static/app.mjs` (bootstrap/router), `static/live.mjs`, `static/stats.mjs`, `static/style.css`; optionally vendor `static/preact-htm.mjs` (single embedded ESM file, no npm); `frontend_test.go`
**REQUIRED SKILL:** invoke **dataviz** before the stats chart. **Decision (closes spec open-question #2):** no-build, no toolchain; per-tab ES modules (never one monolith); a vendored Preact+htm ESM file is permitted for reactivity but no npm/build step. Theme-aware via `prefers-color-scheme`; no external CDN (all assets embedded); attach listeners in JS (no inline handlers).
**Produces:** the shell (tab nav), **Live** (`EventSource('/api/stream')` prepend, initial fill from `/api/decisions`, severity colors), **Stats** (`/api/stats`, inline-SVG severity bar per dataviz + deny/sessions tiles).

- [ ] **Step 1: Failing test** — Go test asserts `/` serves and references the module + css; each `.mjs`/`.css` served non-empty with a sane content-type.
- [ ] **Step 2–4:** implement. PASS.
- [ ] **Step 5: Commit** `feat(web): frontend shell + Live tail + Stats (no-build, per-tab modules)`.

---

### Task 12b: Frontend Explain + Policy editor + versions

**Files:** create `static/explain.mjs`, `static/policy.mjs`; wire into the shell
**Produces:** **Explain** (command/tool/mode/file box → `POST /api/explain` → severity/verdict/rule/facts). **Policy** editor (`GET /api/policy` into a textarea; **Validate & Save** → `PUT /api/policy` with `X-Argus-CSRF:1` + `application/json`; inline 400 errors; success shows new version; a versions list, click to view a snapshot). Note: JSON-Schema autocomplete (spec §3.2) is intentionally out for the no-build editor — validation-on-save is the guarantee.

- [ ] **Step 1: Failing test** — the two modules are served non-empty; (behavioral UI verified in Task 14 driven check).
- [ ] **Step 2–4:** implement. PASS.
- [ ] **Step 5: Commit** `feat(web): frontend Explain + Policy editor/versions`.

---

### Task 12c: Frontend Replay + close-the-loop-from-row

**Files:** create `static/replay.mjs`; add a row action into `live.mjs`/a decisions view
**Produces:** **Replay** (edit/pick a candidate policy → `POST /api/replay` → transition summary + changed-rows table, with the "safe not covered" note). **Close-the-loop:** an "Allow / downgrade" control on each decision row → `POST /api/allowlist {command,tool}` (CSRF header) → toast the new version; UI notes that floor commands can't be downgraded (mirror the server behavior).

- [ ] **Step 1: Failing test** — module served non-empty.
- [ ] **Step 2–4:** implement. PASS.
- [ ] **Step 5: Commit** `feat(web): frontend Replay simulator + close-the-loop from decision row`.

---

### Task 13: `argus serve` CLI

**Files:** Create `internal/cli/serve.go`, `serve_test.go`; Modify `cmd/argus/main.go`
**Produces:** `func Serve(home, addr string, w io.Writer) int` — open DB (`~/.argus/argus.db`), `web.New(store, policyPath, addr)` (error → print + exit non-zero), print the listen URL, `ListenAndServe` until SIGINT/SIGTERM (`signal.NotifyContext`), `defer store.Close()`. Wire `case "serve"` with `--addr` (default `127.0.0.1:4600`).

- [ ] **Step 1: Failing test** — `Serve` on an ephemeral loopback port in a goroutine with a cancelable ctx AND an open SSE client; `GET /api/stats` → 200; cancel → assert `Serve` returns within the bounded window (proves SSE doesn't block shutdown) AND a fresh `store.Open` of the same DB succeeds afterward (proves `Close` ran).
- [ ] **Step 2–4:** implement. PASS.
- [ ] **Step 5: Commit** `feat(cli): argus serve`.

---

### Task 14: `argus doctor` seed-rule WARN (parked Plan-1 Important)

**Files:** Modify `internal/cli/doctor.go`, its test
**Produces:** `Doctor` prints a non-fatal `WARN` when the loaded policy is missing any `policy.SeedRuleIDs()` id (user-edited policy silently losing baseline `medium` coverage). WARN does NOT change the exit code (hard checks still govern 0/non-0).

- [ ] **Step 1: Failing test** — after `Init` (full default) no seed WARN; after overwriting `policy.json` with `{"version":1,"rules":[]}`, `Doctor` returns 0 but output contains a `WARN` naming missing baseline rules.
- [ ] **Step 2–4:** implement via `policy.SeedRuleIDs()`. PASS.
- [ ] **Step 5: Commit** `feat(cli): doctor warns on missing baseline seed rules`.

---

### Task 15: End-to-end integration + driven browser check

**Files:** Create `internal/web/e2e_test.go`
- [ ] **Step 1: Integration test** — `httptest.NewServer(srv.Handler())` over a temp DB; exercise (with the `X-Argus-CSRF` header + correct Host): stats counts; `decisions?severity=high`; SSE receives an inserted row; explain (sudo rm→deny); **Host spoof → 403**; **CSRF-missing PUT → 403**; PUT invalid→400 file-unchanged, valid→200 version-bump with matching snapshot; replay transition present; allowlist downgrades a medium but NOT a floor command. One sequential test, real assertions.
- [ ] **Step 2–3:** make it pass; fix any seam.
- [ ] **Step 4: Driven check (controller, not a unit test):** `argus serve` on a temp home; drive with claude-in-chrome — load `/`, confirm all tabs render, run an explain + a replay + a policy save from the UI, screenshot; record in the report.
- [ ] **Step 5: Commit** `test(web): end-to-end API + security integration`.

---

## Self-Review

**Spec coverage (§3.4, §6, §9):** serve (T5/T13) · live tail SSE (T8/T12a) · stats (T7/T12a; per-project heatmap+trend **explicitly descoped**, stated) · explain view (T9/T12b) · policy editor + versions (T10/T12b; schema-autocomplete **explicitly descoped**, stated) · replay simulator (T3/T4/T11/T12c) · **close-the-loop allow/downgrade from a row (T11/T12c — restored after review F1)** · parked findings: `store.Close()` (T1/T13), doctor seed-WARN (T14). Plans 3–4 out of scope.

**Security (the 3 review BLOCKINGs):** loopback-only bind rejects `0.0.0.0`/empty/`:port`-wildcard (T5); Host-allowlist defeats DNS-rebinding + CSRF on mutating routes (T6); policy version = document version so audit/replay resolve (Global + T10). Mutating routes validate-before-write; bodies size-limited.

**Type consistency:** the "Consumes from Plan 1" appendix pins every reused signature; `Decision` uses `Reason`/`Obfuscated` (singular/bool) — the plan uses those, not "reasons"/"obfuscation". `VerdictCount`/`MaxID`/`DistinctSessions` are owned by Task 1 (not hand-waved in a handler task). `replay.{Change,Result,Rescore,MaxReplay}`, `policy.{Validate,SeedRuleIDs}`, `web.{New,Handler,ListenAndServe}` consistent producer→consumer.

**Right-sizing:** the frontend is split T12a/b/c (each an independently reviewable gate). Backend tasks are one-file-focused.

**Ordering:** T1→T2→T3→T4; T5→T6→(T7…T11 handlers)→T12a→b→c; T13 after server+handlers; T14 independent; T15 last.

## Changelog (rev 1 → rev 2), from two adversarial reviews
**Security BLOCKING fixed:** real loopback-bind (reject wildcard/empty) [T5]; Host-allowlist anti-DNS-rebinding + CSRF [T6]; policy version = document version (audit/replay alignment) [Global/T10]. **Coverage BLOCKING fixed:** close-the-loop allow/downgrade-from-row restored [T11/T12c]. **Should-fixed:** replay scope honest (logged/low+ only, reachable fixtures, safe-not-covered noted) [T3]; `VerdictCount`/`MaxID`/`DistinctSessions(WHERE session!='')` owned by store task [T1]; per-request policy load (no stale/no race) [T9]; bounded shutdown + SSE shutdown-aware (Close runs) [T5/T8/T13]; explain supports Write/Edit `file` [T9]; replay excludes legacy-import rows [T1/T4/T11]; frontend split into 3 tasks + no-build decision recorded + per-tab modules [T12a-c]; "Consumes from Plan 1" appendix + reason/obfuscated naming reconciled. **Nits:** Row.ID ripple fixed at all 3 round-trip sites + json tags (+jsonl key change noted) [T1]; MaxID source method [T1/T8]; ticker.Stop + db-closed log-not-panic [T8]; MaxReplay const [T3]; body-size limit [T6]; Recent-vs-Page dedup [T7]; heatmap/trend + schema-autocomplete descopes stated [T7/T12b].
