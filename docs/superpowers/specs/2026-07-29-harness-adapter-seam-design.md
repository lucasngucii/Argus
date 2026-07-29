# Harness adapter seam — design (Phase 1 of multi-harness)

**Date:** 2026-07-29
**Status:** approved (brainstormed + two adversarial review rounds folded in)
**Scope:** Phase 1 only — a behavior-preserving refactor that carves the
Claude-Code-specific edges into a swappable seam. Codex/Gemini adapters are
later phases and out of scope here.

## 1. Problem & goal

Argus's roadmap calls for gating agents beyond Claude Code (Codex, Gemini). The
pure classifier already works across harnesses; only the **dirty-shell edges**
are Claude-Code-specific: parsing the PreToolUse payload, emitting the verdict
JSON, wiring the hook into config, and the doctor probe. Today those edges are
hardcoded to Claude Code, and `gate.go` records `Harness: "claude-code"` as a
literal.

**Goal:** introduce a harness *adapter* seam so those four edges dispatch by a
selected harness name, leaving `classify(payload, policy) → Decision`
untouched. Phase 1 ships **only** the Claude-Code adapter routed through the new
seam — no observable behavior change — plus the selection mechanism, so a later
phase adds a second adapter by filling in four functions, not by reworking the
hot path.

**Non-goals (Phase 1):** any Codex/Gemini adapter; a TOML config writer; a
PowerShell/alternate-shell parser; splitting `verdict.Map`; changing the
classifier, the policy model, or the store schema.

## 2. Locked decisions (from brainstorming)

1. **Function seam, NOT an interface.** CLAUDE.md forbids an interface for a
   single implementation; only claude-code exists today. An interface may emerge
   in Phase 2 when a second real adapter lands.
2. **Selection via a `--harness` flag**, shipped now, default resolving to
   claude-code. `init` writes `argus gate --harness=<name>` into a harness's
   config. An absent/empty flag resolves to claude-code so existing installs
   whose hook command is a bare `argus gate` keep working unchanged.
3. **Full scope:** Parse + Emit + Wire + Probe are all parameterized by harness
   in Phase 1 (each with the single claude-code impl). This is a deliberate
   user choice over the narrower "hot-path only" alternative; the accepted cost
   is two dispatch switches (Wire/Probe) that carry one impl until Phase 2.

## 3. Architecture

New package **`internal/adapter`** — named `adapter`, not `harness`, to avoid
collision with the existing `RunHarness` corpus-test runner and the
`store.Row.Harness` field (which stays; it is the same identity axis, persisted).
No interface. It imports only `hook` and `verdict` (both leaf packages that
import no `cli`/`adapter` code), so it stays cycle-free.

- `adapter/adapter.go` — `Canonical`, `Parse`, `Emit`, and the `Outcome` type
  (the **hot-path** seam).
- `adapter/claudecode.go` — the Claude-Code `Parse`/`Emit` implementations.

**Package placement — why Wire/Probe do NOT live in `adapter`.** `wireHook` and
`checkHook` live in package `cli` and depend on a cluster of unexported `cli`
helpers (`settingsPath`, `readSettings`, `writeSettings`, `gateEntry`,
`gateCommand`, …). Since `cli` must import `adapter` (Gate/Init/Doctor call it),
putting `Wire`/`Probe` in `adapter` and having them reach back into those helpers
would create a `cli → adapter → cli` import cycle that Go rejects. So the
**`Wire` and `Probe` dispatch switches live in package `cli`** (next to the
helpers they call); the `adapter` package holds only the hot-path seam, which has
no cycle. All four edges are still parameterized by harness (full scope) — two in
`adapter`, two in `cli`.

### 3.1 Canonical — one name authority

```go
// Canonical resolves a harness flag value to its stored/dispatched identity.
// "" (an old install's bare `argus gate`) and "claude-code" both map to
// "claude-code"; any other value is an unknown harness and errors. Callers use
// the returned string for BOTH dispatch and the store row, so a raw flag string
// is never persisted (a mislabelled row would be filtered out of replay/close-loop).
func Canonical(name string) (string, error) {
    switch name {
    case "", "claude-code":
        return "claude-code", nil
    default:
        return "", fmt.Errorf("unknown harness %q", name)
    }
}
```

### 3.2 The four seam points

| Seam | Package | Signature | Claude impl (Phase 1) | A later adapter will |
|------|---------|-----------|-----------------------|----------------------|
| Parse | `adapter` | `Parse(name string, r io.Reader) (hook.Payload, error)` | calls existing `hook.Parse` | map its own payload JSON → `hook.Payload` |
| Emit  | `adapter` | `Emit(name string, w io.Writer, o Outcome) int` | writes Claude `hookSpecificOutput` JSON; returns 2 on write failure | serialize its own decision shape + translate capability |
| Wire  | `cli` | `Wire(name, home string) error` | existing `wireHook` | write its own config (e.g. `~/.codex/config.toml`) |
| Probe | `cli` | `Probe(name, home string) error` | existing `checkHook` + harness discovery | probe its own config |

Each dispatch function is a `switch name` with one case plus a fail-closed
`default`. The switches match **canonical** names only (`"claude-code"`); an
empty or unknown `name` falls through to `default` — do not add a redundant
`case ""`, since `Canonical` is the single name authority and callers pass its
output. `Probe` returns plain `error` (not a new type): it slots directly into
doctor's existing `report(label string, err error)` convention — `nil ⇒ PASS`,
non-nil ⇒ `FAIL %v`. `hook.Payload` (the normalized form the classifier
consumes) and `verdict.Map` stay in core, shared. Only JSON-in (Parse) and
JSON-out (Emit) are harness-specific.

### 3.3 Outcome and the Emit contract

```go
// Outcome is what an adapter serializes. Phase 1 needs only the verdict and its
// reason; the struct form (not scalars) lets a later adapter add fields — e.g.
// a tool-use id — without a signature change. It deliberately does NOT carry the
// full Payload in Phase 1, so an adapter cannot re-derive or override the verdict.
type Outcome struct {
    Verdict string // "allow" | "ask" | "deny" — the verdict Gate decided to emit
                   // (post-shadow: shadow mode sets this to "allow")
    Reason  string
}
```

**Emit contract (binding):**
- Emit owns the fail-closed *outcome*, not just the bytes. The Claude rule
  "empty stdout ⇒ Claude Code treats it as no-opinion ⇒ tool runs unprompted, so
  a failed write must fail-closed via exit code 2" now lives inside the claude
  adapter. `Emit` returns the exit code the process should use (0 normal, 2
  fail-closed).
- An adapter may only translate a verdict in the **more-restrictive** direction
  (`allow → ask → deny`), never looser. It may read `Outcome` only to serialize;
  it may never change the verdict it was handed. (A later deny-only adapter's
  `ask → deny` collapse is the sanctioned use of this.)

### 3.4 gate flow (the hot path)

`cmd/argus/main.go` gate case parses argv with `flag.NewFlagSet(...,
flag.ExitOnError)` (mirrors `serve`/`stats`), a `--harness` string defaulting to
`""`, and passes it into `Gate(stdin, stdout, home, harness)`. `Gate`'s
signature change and `main` passing the new argument land in the **same commit**
so the build never breaks mid-step. A malformed flag (a typo like `--harnes=x`)
makes `ExitOnError` call `os.Exit(2)` *before* `Gate` runs — no classification
was possible, and exit 2 blocks the tool, so this is an acceptable fail-closed
outside the recover.

Inside `Gate` (all under the existing top-level `recover` that fail-closes to
deny):

1. `name, err := adapter.Canonical(harness)`, resolved **early**, with `name`
   declared in `Gate`'s outer scope so the deferred recover closure captures it.
2. **On `Canonical` error (unknown harness): `return 2` immediately — do NOT
   route through `adapter.Emit`.** We provably cannot speak an unknown harness's
   protocol, and emitting a *claude-format* deny to some other real harness would
   be ignored (foreign JSON) while exit 0 lets the tool run — a fail-open on a
   dangerous path. A non-zero hook exit is the only portable "do not proceed"
   signal. The reason goes to stderr.
3. Otherwise the terminal paths funnel through **one** `adapter.Emit(name, w,
   Outcome{...})` call site on the main path, and `Gate` returns whatever code it
   yields. There are **exactly two `Emit` call sites total**: this main-path one,
   and the deferred `recover` closure (which must assign `Emit`'s returned code to
   the named return so a failed-write's exit 2 is never dropped). No branch may
   call `Emit` and then `return 0` independently — that would fail open. Each
   terminal path builds an explicit `Outcome`, never a zero value:
   - `hook.Parse` error → `Outcome{Verdict: "deny", Reason: "unparseable payload"}`
     (a zero-value `Outcome{}` would serialize `permissionDecision:""`, which
     Claude Code does not treat as deny → fail-open; the pre-refactor code
     hardcoded `"deny"` here).
   - shadow mode → `Outcome{Verdict: "allow", …}` (records the real verdict, emits allow).
   - normal → `Outcome{Verdict: verdict.Map(...), Reason: decision.Reason}`.
4. `recordDecision` writes `Harness: name` (the Canonical value), never the raw
   flag. It is best-effort and independent of the verdict (invariant §3).

**Shadow mode and `verdict.Map` stay in core.** Shadow (`pol.Defaults.Shadow`:
emit "allow" but record the real verdict) is Argus policy, harness-independent —
`Gate` applies it before handing the Outcome to `Emit`. `verdict.Map(severity,
permissionMode)` stays in core for Phase 1, but this design explicitly does **not**
claim it is harness-neutral: its `permissionMode`/`interactiveModes` half is a
Claude-specific safety judgment and will be split per-harness in a later phase.
Only the severity floor (`high → deny`) is universal.

### 3.5 Wire / Probe (dispatch in package `cli`, full scope)

- `Wire(name, home) error` is a `switch name` in `cli`; the claude case is the
  existing `wireHook`. On **fresh** wiring it writes the command
  `argus gate --harness=claude-code`. It does **not** self-heal an existing bare
  `argus gate` command — a blind append is pointless (the bare form already
  resolves to claude-code via the default) and can corrupt a user's customized
  command or shell operators. The match constant stays bare
  `gateCommand = "argus gate"`; the written "wire command" is distinct from it.
  **Requirement on every adapter (present and future):** a harness's wire command
  MUST contain `gateCommand` (`"argus gate"`) as a substring, so `gateEntry`/
  doctor recognize it and stay idempotent. `argus gate --harness=claude-code`
  satisfies this; a Phase-2 adapter that wired a differently-named invocation
  would silently break duplicate-detection and re-append on every `init`.
- `Probe(name, home) error` is a `switch name` in `cli`; the claude case is the
  existing `checkHook`, extended with **harness discovery**: doctor reads the
  wired command in `settings.json` and extracts the configured harness with a
  fixed rule — **match `--harness=` followed by one run of non-whitespace
  characters (the `=` form only, exactly what `init` writes)**; the
  space-separated form (`--harness x`) and a single dash are NOT recognized and
  read as absent; absent ⇒ `""`. The extracted value goes through `Canonical`,
  yielding a tri-state: **bare (`""`) = PASS, known = PASS, unknown = FAIL**
  (a non-nil error naming the offending value, rendered by doctor's `report` as
  `FAIL %v`). Without this, a hook wired with `--harness=bogus` would PASS doctor
  while every live call denies (the blind-operator failure).

## 4. Invariants & how they hold

1. **Pure core** — `classify` is not in the seam; untouched.
2. **Hot path never fails open** — the `default` switch case and the unknown-
   harness `return 2` both block; the single-choke-point Emit rule prevents a
   dropped exit code.
3. **Verdict independent of writes** — `recordDecision` still runs after the
   verdict is computed; `Harness: name` is a label, not an input to the verdict.
4. **`high` is a floor** — enforced in the pure core; additionally the Emit
   more-restrictive-only contract + a golden test (below) keep a deny from being
   relaxed in the new serialize layer.
5. **Self-protection stays high** — lives in `classify`; the seam does not touch
   it. `Wire` with an unknown name errors (init fails loudly) rather than writing
   to an attacker-chosen path.

## 5. Testing

- **Regression:** the entire existing golden + evasion corpus stays green
  (classify untouched).
- **Byte-identity:** the claude `Emit` delegates to the untouched `verdict.Emit`,
  so `--harness=claude-code` output is asserted equal to `verdict.Emit`'s output
  for the same verdict/reason — captured as a `testdata/` golden per
  representative payload (allow / ask / deny). No behavior may differ from the
  pre-refactor gate.
- **Default:** no `--harness` flag == `claude-code` (bare-install path).
- **Fail-closed unknown:** `--harness=bogus` → exit code 2 (asserted non-allow /
  non-zero), and specifically **not** a claude-format allow/no-opinion.
- **Choke-point fail-closed (parse-error branch):** inject a failing `stdout`
  `io.Writer` (Gate's `stdout` parameter is the seam) on a payload that fails
  `hook.Parse`, and assert exit 2 — proving the terminal Emit's exit code is
  honored, not dropped to 0. (A write failure does not itself panic, so it does
  not reach the recover branch; the recover path is covered by the recover-branch
  test below, not by a failing writer.)
- **Recover branch:** the top-level `recover`→deny path is driven by a test-only
  injected panic (a test seam that makes `classify`/`Parse` panic) and asserts the
  emitted verdict is `deny` and the exit code reflects `Emit`'s return. If no such
  injection seam is added in Phase 1, this assertion is scoped to what is
  reachable and the seam is added when first needed — but the parse-error test
  above already pins the exit-code-honoring contract.
- **Invariant §4 golden:** a **high/deny** `Outcome` never yields
  allow/ask/no-opinion out of `Emit` (deny stays deny).
- **Store label:** an un-re-init'd upgrade (bare `argus gate`) records
  `harness = "claude-code"`, so `replay`/close-loop's `claudeCodeOnly` filter
  still includes the rows.
- **init / doctor:** fresh `Wire` writes `--harness=claude-code`; doctor PASSes a
  bare command and a `--harness=claude-code` command, and FAILs a
  `--harness=bogus` command.

## 6. Deferred / noted (not Phase 1)

- **`settings.local.json` duplicate wiring** — pre-existing: `wireHook`/`Probe`
  only inspect `settings.json`, so a hook living in `settings.local.json` is
  invisible and `Wire` would append a duplicate. Out of scope; documented so the
  "fresh wiring" logic's single-file assumption is explicit.
- **Shared §4 enforcement across adapters** — Phase 1 relies on a per-adapter
  golden; when a second adapter lands, add a table-driven test in `adapter/` that
  iterates every registered name × {deny, ask, allow} so a new adapter cannot opt
  out of the more-restrictive-only assertion.
- **`verdict.Map` per-harness split** — the permissionMode-downgrade half becomes
  a per-harness verdict policy when a harness with different prompting semantics
  arrives.

## 7. Open items

None blocking. The two review-round Blockers (unknown-harness fail-open;
doctor-discovery hole) are resolved in §3.4 step 2 and §3.5 respectively.
