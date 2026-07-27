# Argus Web Control-Plane — Implementation Plan (Plan 2 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. REQUIRED before each task: read `CLAUDE.md` and invoke the **argus-architect** skill. The frontend task additionally requires the **dataviz** skill before writing any chart code.

**Goal:** Add the local observability + governance UI on top of the Plan-1 engine: an `argus serve` localhost web app (live decision tail, stats, policy editor, explain, and the **replay simulator**) plus an `argus replay` CLI — the features a stateless deny-list structurally cannot offer.

**Architecture:** A `net/http` server (localhost-only) serving a JSON+SSE API and a **no-build** static frontend embedded via `//go:embed`. The moat is a pure **replay engine** that re-scores stored decisions against a candidate policy and diffs the outcome. The security verdict path (Plan 1) is untouched; this plane only reads the DB and, for the policy editor, validates-then-writes `policy.json` + a version snapshot.

**Tech Stack:** Go 1.26 · stdlib `net/http`, `html/template`, `embed`, `encoding/json` · reuse `internal/{store,policy,classify,verdict,hook,shellast}` · **frontend: hand-written HTML/CSS/vanilla JS with inline SVG charts — NO npm/node/vite/framework** (keeps the whole project pure-Go-buildable, `CGO_ENABLED=0`, one `go build`).

## Global Constraints

- Module `github.com/lucasngucii/argus`. Go **1.26**. **`CGO_ENABLED=0`** — no cgo, and **no JS build toolchain** (no `package.json`, no `node_modules`); the frontend is static files embedded with `//go:embed`.
- **Bind localhost only** (`127.0.0.1`), default port `4600`, overridable via `--addr`. No auth (single-user local), no CORS headers, no `0.0.0.0`. The server must never expand the gate's attack surface.
- **Read-mostly.** The only mutating endpoint is `PUT /api/policy`, which MUST `policy.Load`-validate the body against the schema BEFORE writing `policy.json`, then record a `policy_versions` snapshot. A rejected/invalid policy leaves the on-disk policy unchanged.
- **The engine is authoritative and reused, never reimplemented.** Stats/explain/replay all call `classify.Classify` / `verdict.Map` / `policy.Load` — no parallel classification logic in the web layer.
- **Replay is pure and read-only:** it never writes decisions and never mutates `policy.json`; it reconstructs a `hook.Payload` from a stored `store.Row` and classifies it against a candidate policy in memory.
- **`store` must gain `Close()`** (parked from Plan 1 Task 11 — a long-running `serve` that never closes leaks the `*sql.DB` pool + its goroutine).
- Commit identity author & committer `lucasngucii <lucasalehwork@gmail.com>`; **never** a `Co-Authored-By: Claude` trailer.
- Paths: DB `~/.argus/argus.db`, policy `~/.argus/policy.json` (same as Plan 1).

## File Structure

```
argus/
  internal/store/store.go            # +Close(), +Row.ID, +DecisionsAfter, +Page, +PolicyVersions/+PolicyVersionJSON, +AllDecisions
  internal/replay/replay.go          # pure re-score + diff engine
  internal/web/server.go             # http.Server, routing, localhost bind, graceful shutdown
  internal/web/handlers.go           # /api/* handlers
  internal/web/sse.go                # SSE live-tail hub
  internal/web/static/index.html     # embedded SPA shell (no build)
  internal/web/static/app.js         # vanilla JS: tabs, fetch, EventSource, replay, editor
  internal/web/static/style.css      # theme-aware (light/dark) styles
  internal/web/embed.go              # //go:embed static/*
  internal/cli/serve.go              # `argus serve`
  internal/cli/replay.go             # `argus replay`
  internal/cli/doctor.go             # MODIFY: warn when loaded policy misses seed rule IDs
  cmd/argus/main.go                  # wire `serve`, `replay`
```

---

### Task 1: Store read-surface + `Close()` + `Row.ID`

**Files:** Modify `internal/store/store.go`, `internal/store/store_test.go`
**Interfaces — Produces:**
- `func (s *Store) Close() error` — closes the underlying `*sql.DB`.
- `Row` gains `ID int` (first field). `Recent` selects/scans `id`.
- `func (s *Store) DecisionsAfter(afterID, limit int) ([]Row, error)` — rows with `id > afterID`, oldest-first, up to limit (SSE cursor).
- `func (s *Store) Page(severity string, limit, beforeID int) ([]Row, error)` — filtered page, newest-first; empty `severity` = all; `beforeID<=0` = from newest.
- `func (s *Store) DistinctSessions() (int, error)`.
- `type VersionMeta struct { Version int; TS, Author, Note, Hash string }`; `func (s *Store) PolicyVersions() ([]VersionMeta, error)` (newest-first) and `func (s *Store) PolicyVersionJSON(version int) (string, error)`.
- `func (s *Store) AllDecisions(cap int) (rows []Row, capped bool, err error)` — full history oldest-first up to `cap`; `capped=true` when truncated (no silent cap — replay logs it).

- [ ] **Step 1: Write failing tests** (add to store_test.go)
```go
func TestCloseIsIdempotentSafe(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	if err := s.Close(); err != nil { t.Fatalf("close: %v", err) }
}
func TestDecisionsAfterCursor(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	for i := 0; i < 3; i++ { _ = s.Insert(Row{TS: "t", Severity: "low"}) }
	first, _ := s.DecisionsAfter(0, 10)
	if len(first) != 3 || first[0].ID == 0 { t.Fatalf("want 3 rows with ids, got %+v", first) }
	tail, _ := s.DecisionsAfter(first[1].ID, 10)
	if len(tail) != 1 || tail[0].ID != first[2].ID { t.Fatalf("cursor wrong: %+v", tail) }
}
func TestPageFilterBySeverity(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	_ = s.Insert(Row{TS: "t", Severity: "high"}); _ = s.Insert(Row{TS: "t", Severity: "low"})
	hi, _ := s.Page("high", 10, 0)
	if len(hi) != 1 || hi[0].Severity != "high" { t.Fatalf("filter: %+v", hi) }
}
func TestPolicyVersionsRoundTrip(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	_ = s.InsertPolicyVersion(1, "init", "seed", `{"version":1}`, "abc")
	vs, _ := s.PolicyVersions()
	if len(vs) != 1 || vs[0].Version != 1 || vs[0].Author != "init" { t.Fatalf("versions: %+v", vs) }
	js, _ := s.PolicyVersionJSON(1)
	if js != `{"version":1}` { t.Fatalf("json: %q", js) }
}
func TestAllDecisionsCapFlag(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	for i := 0; i < 5; i++ { _ = s.Insert(Row{TS: "t", Severity: "low"}) }
	rows, capped, _ := s.AllDecisions(3)
	if len(rows) != 3 || !capped { t.Fatalf("want capped 3, got %d capped=%v", len(rows), capped) }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement.** Add `ID` as the first `Row` field; update the `Recent` SELECT to `SELECT id, ts, …` and its `Scan` to `&r.ID, &r.TS, …`. **Cross-task ripple to fix in the same step:** `store_test.go`'s existing `TestRecentRoundTrip` compares whole `Row` structs — after adding `ID`, the returned rows carry real ids while the `want` literals have `ID:0`; update that test to zero out `got[i].ID` before the struct compare (or assert ids separately). `Insert` is unchanged (`id` is autoincrement). New methods are plain queries.
- [ ] **Step 4: Run → PASS** (`go test ./internal/store/...` and full `go test ./...` — confirm gate/stats still green, since `Row` now has `ID`).
- [ ] **Step 5: Commit** `feat(store): add Close, Row.ID, cursor/page/version/all read methods`.

---

### Task 2: Replay engine (the moat) — pure re-score + diff

**Files:** Create `internal/replay/replay.go`, `internal/replay/replay_test.go`
**Interfaces — Produces:**
- `type Change struct { Row store.Row; OldSeverity, NewSeverity, OldVerdict, NewVerdict string }`
- `type Result struct { Total int; Changed []Change; Summary map[string]int; Capped bool }` — `Summary` keys like `"ask->allow"`, `"allow->deny"`, counts of transitions among changed rows.
- `func Rescore(rows []store.Row, capped bool, candidate policy.Policy) Result` — pure; for each row, rebuild a `hook.Payload{ToolName:r.Tool, PermissionMode:r.PermissionMode, CWD:r.CWD, ToolInput:{Command:r.Command, FilePath:r.File}}`, run `classify.Classify(payload, candidate)` → new severity, `verdict.Map(newSeverity, r.PermissionMode)` → new verdict; compare to the row's stored `Severity`/`Verdict`; collect only rows whose severity OR verdict changed.

- [ ] **Step 1: Write failing tests**
```go
func TestRescoreDetectsNewlyCaught(t *testing.T) {
	rows := []store.Row{{Tool: "Bash", Command: "sudo rm -rf /", PermissionMode: "default", Severity: "safe", Verdict: "allow"}}
	res := replay.Rescore(rows, false, policy.Default())
	if len(res.Changed) != 1 || res.Changed[0].NewVerdict != "deny" { t.Fatalf("should newly catch: %+v", res.Changed) }
	if res.Summary["allow->deny"] != 1 { t.Fatalf("summary: %+v", res.Summary) }
}
func TestRescoreUnchangedNotReported(t *testing.T) {
	rows := []store.Row{{Tool: "Bash", Command: "ls -la", PermissionMode: "default", Severity: "safe", Verdict: "allow"}}
	if len(replay.Rescore(rows, false, policy.Default()).Changed) != 0 { t.Fatal("benign unchanged must not appear") }
}
func TestRescorePropagatesCapped(t *testing.T) {
	if !replay.Rescore(nil, true, policy.Default()).Capped { t.Fatal("capped must propagate") }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `Rescore` as specified; `Total = len(rows)`; build `Summary` from `fmt.Sprintf("%s->%s", oldVerdict, newVerdict)` for each changed row.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(replay): pure re-score/diff engine (candidate policy vs stored decisions)`.

---

### Task 3: `argus replay` CLI

**Files:** Create `internal/cli/replay.go`, `internal/cli/replay_test.go`; Modify `cmd/argus/main.go`
**Interfaces — Produces:** `func Replay(s *store.Store, candidate policy.Policy, w io.Writer) int` — read all decisions (`AllDecisions(50000)`), `replay.Rescore`, print the summary (`N decisions, M changed`, the transition table) and each changed row (`old→new`); if `capped`, print a `NOTE: only first 50000 decisions scored` line. Return 0.

- [ ] **Step 1: Failing test** — seed 1 `safe/allow` row whose command is `sudo rm -rf /`, call `Replay(s, policy.Default(), buf)`; assert output contains `allow->deny` and `1 changed`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**; wire `case "replay"` in main.go: open DB, load candidate from `--policy FILE` (default: current `~/.argus/policy.json`) or `--version N` (via `store.PolicyVersionJSON`), call `Replay`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(cli): argus replay — re-score history against a candidate policy`.

---

### Task 4: HTTP server scaffold + localhost bind + embedded static + graceful shutdown

**Files:** Create `internal/web/server.go`, `internal/web/embed.go`, `internal/web/static/index.html` (minimal placeholder ok for THIS task), `internal/web/server_test.go`
**Interfaces — Produces:**
- `//go:embed static/*` → `var staticFS embed.FS` (in embed.go).
- `type Server struct { … }`; `func New(s *store.Store, policyPath string, addr string) *Server`; `func (srv *Server) Handler() http.Handler` (returns the mux — testable with `httptest`); `func (srv *Server) ListenAndServe(ctx context.Context) error` (binds `addr`, serves, shuts down gracefully on ctx cancel).
- Route `GET /` and `GET /static/*` → embedded files; unknown `/api/*` → 404 JSON.

- [ ] **Step 1: Failing tests** (use `net/http/httptest` on `Handler()`)
```go
func TestServesIndex(t *testing.T) {
	srv := web.New(testStore(t), "", "127.0.0.1:0")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<") { t.Fatalf("index: %d", rec.Code) }
}
func TestUnknownApiIs404JSON(t *testing.T) {
	srv := web.New(testStore(t), "", "127.0.0.1:0")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/nope", nil))
	if rec.Code != 404 { t.Fatalf("want 404, got %d", rec.Code) }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement.** `Handler()` wires an `http.ServeMux`: `/` and `/static/` from `staticFS` via `http.FileServerFS`; `/api/` handlers (added next tasks) default to a JSON 404. `ListenAndServe` uses `http.Server` + `srv.Shutdown` on `ctx.Done()`. Reject non-loopback `addr` hosts (only `127.0.0.1`/`localhost`/empty-host) — return an error from `New`/`ListenAndServe` if asked to bind a public interface. `index.html` can be a one-line placeholder in this task (real UI in Task 11).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(web): http server scaffold — embedded static, localhost-only bind, graceful shutdown`.

---

### Task 5: `GET /api/stats`

**Files:** Create `internal/web/handlers.go`, `internal/web/handlers_test.go`
**Interfaces — Produces:** handler for `GET /api/stats` → JSON `{counts: {severity:n}, deny: n, sessions: n, recent: [Row…]}` using `store.Counts`, a deny tally (from `Counts`? no — deny is a verdict; compute via a small `store` deny count or derive from `Page`), `store.DistinctSessions`, `store.Recent(50)`.
- Consumes: `store.{Counts,DistinctSessions,Recent}`.
- Note: add `func (s *Store) VerdictCount(verdict string) (int, error)` to store if a deny count isn't otherwise available (keep minimal; or count denies within `Recent` and label it "recent deny" — prefer a real full-history `VerdictCount`).

- [ ] **Step 1: Failing test** — insert 1 high/deny + 2 low/allow; `GET /api/stats`; assert JSON decodes and `counts.high==1`, `counts.low==2`, `deny>=1`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**; if adding `VerdictCount`, add its store test in Task 1's file style (small).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(web): GET /api/stats`.

---

### Task 6: `GET /api/decisions` (filtered page)

**Files:** Modify `internal/web/handlers.go`, `handlers_test.go`
**Interfaces — Produces:** `GET /api/decisions?severity=&limit=&before=` → JSON `{rows: [Row…], nextBefore: id}` via `store.Page`. `limit` clamped to `[1,200]` default 50.

- [ ] **Step 1: Failing test** — insert high+low+low; `GET /api/decisions?severity=low` → 2 rows all low. `GET /api/decisions?limit=1` → 1 row + `nextBefore` set.
- [ ] **Step 2: Run → FAIL.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(web): GET /api/decisions (severity filter + pagination)`.

---

### Task 7: `GET /api/stream` — SSE live tail

**Files:** Create `internal/web/sse.go`, `internal/web/sse_test.go`; Modify `handlers.go`
**Interfaces — Produces:** `GET /api/stream` sets `Content-Type: text/event-stream`, and on a ticker polls `store.DecisionsAfter(lastID, 100)`, emitting each new row as one SSE `data: <json>\n\n` event; starts the cursor at the current max id (only pushes rows recorded after connect). Respects request-context cancellation (client disconnect) and a poll interval constant (default 1s; injectable in tests).

- [ ] **Step 1: Failing test** — with a fast poll interval, open the stream via `httptest` server in a goroutine with a cancelable context, `Insert` a row, read from the response body, assert one `data:` line containing the row's severity arrives; then cancel and confirm the handler returns.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** with a `flusher, _ := w.(http.Flusher)` push loop; guard when the writer is not a Flusher (return 500). Make the poll interval a package var or a `New`-time field so the test can set it small.
- [ ] **Step 4: Run → PASS** (use a bounded read with a timeout so the test can't hang).
- [ ] **Step 5: Commit** `feat(web): GET /api/stream — SSE live decision tail`.

---

### Task 8: `POST /api/explain`

**Files:** Modify `handlers.go`, `handlers_test.go`
**Interfaces — Produces:** `POST /api/explain` body `{command,tool,cwd,mode}` → JSON `{severity, ruleId, reason, verdict, obfuscated, commands:[…], pipeSinks:[…]}` by building a `hook.Payload`, running `classify.Classify` against the server's current loaded policy, `verdict.Map`, and `shellast.Extract` for the facts. Reuses the engine — no reclassification logic here.

- [ ] **Step 1: Failing test** — `POST /api/explain {"command":"sudo rm -rf /","tool":"Bash","mode":"default"}` → `severity=="high"`, `verdict=="deny"`, non-empty `ruleId`.
- [ ] **Step 2: Run → FAIL.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(web): POST /api/explain`.

---

### Task 9: `GET/PUT /api/policy` + versions (close-the-loop editor)

**Files:** Modify `handlers.go`, `handlers_test.go`
**Interfaces — Produces:**
- `GET /api/policy` → `{json: <current policy.json text>, versions: [VersionMeta…]}`.
- `PUT /api/policy` body = candidate policy JSON → **validate via `policy` schema loader FIRST**; on invalid, `400` with the error and **leave `policy.json` untouched**; on valid, write `policy.json`, then `store.InsertPolicyVersion(maxVersion+1, "web", note, json, sha256)`, return `{version: N}`.
- `GET /api/policy/versions/{v}` → that snapshot's JSON.

- [ ] **Step 1: Failing tests** — `PUT` an invalid policy (`{"version":"x"}`) → 400 and the on-disk file is unchanged; `PUT` a valid minimal policy → 200, `policy.json` updated, a new `policy_versions` row exists; `GET /api/policy` returns the new json + a versions list.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement.** Compute `maxVersion` from `store.PolicyVersions()`. Use `policy.Load` semantics for validation — refactor a `policy.Validate([]byte) error` helper if `Load` only takes a path (add it to `internal/policy` with a tiny test; it wraps the existing schema-validate path).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(web): GET/PUT /api/policy with schema-validate + version snapshot`.

---

### Task 10: `POST /api/replay`

**Files:** Modify `handlers.go`, `handlers_test.go`
**Interfaces — Produces:** `POST /api/replay` body = candidate policy JSON → validate → `store.AllDecisions(50000)` → `replay.Rescore` → JSON `{total, changed:[…], summary:{…}, capped}`.

- [ ] **Step 1: Failing test** — seed a `safe/allow` row with command `sudo rm -rf /`; `POST /api/replay` with `policy.Default()` JSON → `summary["allow->deny"]==1`, `total>=1`.
- [ ] **Step 2: Run → FAIL.** — [ ] **Step 3: Implement** (reuse the Task 9 validator). — [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(web): POST /api/replay — simulate a candidate policy over history`.

---

### Task 11: Frontend (no-build, embedded) — live tail, stats, explain, policy editor, replay

**Files:** Replace `internal/web/static/index.html`; create `internal/web/static/app.js`, `internal/web/static/style.css`; Create `internal/web/frontend_test.go`
**REQUIRED SKILL for the implementer:** invoke **dataviz** before writing the stats chart, and follow its palette/mark guidance; theme-aware light/dark per `prefers-color-scheme`.
**Interfaces — Produces:** a single-page app (vanilla JS, no framework, no build) with tabs:
- **Live** — `EventSource('/api/stream')` prepending rows; severity color (high=red, medium=amber, low=neutral); initial fill from `/api/decisions`.
- **Stats** — `/api/stats`; a severity-distribution bar (inline SVG, dataviz palette), deny/sessions tiles.
- **Explain** — a command box → `POST /api/explain` → shows severity/verdict/rule/facts.
- **Policy** — `GET /api/policy` into a `<textarea>`; **Validate & Save** → `PUT /api/policy` (show 400 errors inline, success shows new version); a versions list.
- **Replay** — edit/pick a candidate policy → `POST /api/replay` → render the transition summary + the changed-rows table (*"this change flips N ask→allow and newly catches M"*).

- [ ] **Step 1: Failing test** — a Go test (`frontend_test.go`) asserts the embedded `index.html` is served at `/` and references `app.js`/`style.css`, and that `app.js`/`style.css` are served with sane content-types and non-empty bodies via `Handler()`. (UI logic itself is verified by the driven browser check in Task 13, not unit tests.)
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the three static files. Keep `app.js` dependency-free (fetch, EventSource, DOM). No inline event-handler attributes that would need unsafe-inline if a CSP is added later — attach listeners in JS. No external CDN references (all assets local/embedded).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(web): no-build embedded frontend — live tail, stats, explain, policy editor, replay`.

---

### Task 12: `argus serve` CLI

**Files:** Create `internal/cli/serve.go`, `internal/cli/serve_test.go`; Modify `cmd/argus/main.go`
**Interfaces — Produces:** `func Serve(home, addr string, w io.Writer) int` — open the DB (`~/.argus/argus.db`), build `web.New`, print the listen URL to `w`, run `ListenAndServe` until SIGINT/SIGTERM (signal.NotifyContext), then `store.Close()` on shutdown. Wire `case "serve"` with a `--addr` flag (default `127.0.0.1:4600`).

- [ ] **Step 1: Failing test** — start `Serve` on `127.0.0.1:0`-style ephemeral (or call the server on an OS-assigned port) in a goroutine with a context, `GET /api/stats`, assert 200, then cancel and confirm clean return + `store.Close()` called (no leaked handle — assert a second `Open` of the same DB works). Keep it hermetic with a temp home.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**; ensure `store.Close()` runs on shutdown (defer).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(cli): argus serve — localhost control-plane`.

---

### Task 13: `argus doctor` seed-rule warning (parked Important from Plan-1 final review)

**Files:** Modify `internal/cli/doctor.go`, `internal/cli/init_test.go` (or doctor_test.go)
**Interfaces — Produces:** extend `Doctor` to add a non-fatal **WARN** line when the loaded `policy.json` is missing any of `Default()`'s baseline rule IDs (`rm-recursive`, `git-danger`, `sudo`, `docker-service`, `db-write`, `opaque-exec`) — a user-edited policy silently losing baseline `medium` coverage. WARN does NOT flip `Doctor`'s exit code (still 0 if the hard checks pass); it only surfaces the gap.

- [ ] **Step 1: Failing test** — after `Init` (full default policy) `Doctor` prints no seed WARN; after overwriting `policy.json` with `{"version":1,"rules":[]}`, `Doctor` still returns 0 (hard checks pass) BUT its output contains a `WARN` mentioning the missing baseline rules.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — compare loaded rule IDs against a `policy.SeedRuleIDs()` helper (add it to `internal/policy`, derived from `Default()`).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** `feat(cli): doctor warns when policy is missing baseline seed rules`.

---

### Task 14: End-to-end server integration + driven browser check

**Files:** Create `internal/web/e2e_test.go`
**Interfaces — Consumes:** the whole `web` + `store` + engine stack.

- [ ] **Step 1: Write the integration test** — spin the `Server.Handler()` in `httptest.NewServer`, then exercise the full API surface against a temp DB: seed decisions; `GET /api/stats` (counts correct); `GET /api/decisions?severity=high`; open `/api/stream`, insert a row, receive the SSE event; `POST /api/explain` (sudo rm → deny); `PUT /api/policy` invalid → 400 + file unchanged, valid → 200 + version bump; `POST /api/replay` (allow→deny transition present). One test, sequential, all assertions real.
- [ ] **Step 2: Run → FAIL** (until all prior tasks land — this task runs last).
- [ ] **Step 3: Make it pass**; fix any integration seam it exposes.
- [ ] **Step 4: Driven check (not a unit test):** the controller (not this test) will `argus serve` on a temp home and drive the page with the claude-in-chrome browser tools — load `/`, confirm Live/Stats/Explain/Policy/Replay tabs render, run an explain and a replay from the UI, and screenshot. Record the result in the task report.
- [ ] **Step 5: Commit** `test(web): end-to-end API integration across the control-plane`.

---

## Self-Review

**Spec coverage (design §3.4, §6):** `serve` (T4/T12) · live tail SSE (T7) · stats (T5) · policy editor GET/PUT + versions (T9) · replay simulator engine+API+CLI (T2/T3/T10) · explain view (T8) · embedded no-build frontend (T11). Parked findings folded in: `store.Close()` (T1/T12), doctor seed-rule warn (T13). Distribution (Plan 3) and MCP/multi-harness (Plan 4) remain out of scope.

**Placeholder scan:** no "TBD"; every task has exact endpoints, signatures, and concrete test assertions. The only intentionally-minimal artifact is Task 4's placeholder `index.html`, explicitly replaced in Task 11.

**Type consistency:** `store.Row` (now with `ID`), `store.{Close,DecisionsAfter,Page,DistinctSessions,PolicyVersions,PolicyVersionJSON,AllDecisions,VerdictCount}`, `replay.{Change,Result,Rescore}`, `web.{New,Handler,ListenAndServe}`, `policy.{Validate,SeedRuleIDs}` are declared where produced and consumed with matching names/signatures. `Rescore` reconstructs `hook.Payload` with the exact field names from Plan 1 (`ToolName,PermissionMode,CWD,ToolInput{Command,FilePath}`).

**Ordering:** T1→T2→T3 (store→replay→CLI); T4 before T5-T11 (server before handlers/frontend); T14 last. T13 is independent (can slot anywhere after T1).

**Security note:** the only new attack surface is the localhost server; mitigated by loopback-only bind (T4 rejects public hosts), no auth needed for single-user local, schema-validation before any policy write (T9), and replay/stats/explain being read-only reuse of the authoritative engine.
