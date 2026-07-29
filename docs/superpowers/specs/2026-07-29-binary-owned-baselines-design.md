# Binary-Owned Baseline Rules + Thin Override Layer — Design Spec

> **Status:** design approved, plan pending.
> **Problem class this eliminates:** a stale `policy.json` silently missing
> baseline protections that a newer binary ships. After this change, baseline
> rules can never be stale, and no re-`init` is ever required after an update.

## 0. Motivation

Argus rules fall into two lifecycles today:

- **Floor + self-protect** (`Floor()`, `SelfProtectRules()`): live in the binary,
  applied as a separate pass in `classify` (`classify.go` `consider(policy.Floor())`).
  They are **never** written to `policy.json`, so upgrading the binary upgrades
  them automatically. This is why a catastrophe rule can never go stale.
- **Baseline seed rules** (`Default().Rules` — `sudo`, `git-danger`, `npm`
  install, the `mcp-*` medium rules, …): copied into `~/.argus/policy.json` at
  `init` and **never refreshed**. A binary that adds a new seed rule cannot
  reach an existing install — the file froze at install time. `doctor` only
  *warns*; the remedy is a lossy manual regenerate.

The two lifecycles should be one. This spec makes baseline seed rules
**binary-owned** exactly like the floor: the file no longer stores them. What
the file stores instead is a **thin layer of the user's intent** — per-baseline
overrides (`enabled` / `severity`) plus user-authored rules (allowlist +
custom). Baselines are reassembled from the binary on every load, so they are
always current; the user's overrides are applied on top.

This is the same architectural move the floor already proved: the binary owns
the non-negotiable ruleset; the file owns a small, well-bounded override layer.

## 1. Scope

**In scope**
- A binary-owned baseline rule set (`Baseline()`), reassembled every load.
- A thin on-disk policy format: `overrides` (baseline tweaks) + `rules` (user).
- Backward-compatible load of existing (old-format) policy files, via a single
  `normalize` step that folds an inline baseline's `enabled`/`severity` edit into
  an override (migration fidelity **M1**). Scope of M1 is exactly the override
  surface: an `enabled` or `severity` edit to a baseline is preserved; a baseline
  copy that differs only in `match`/`reason` is intentionally discarded (the
  binary now owns those — that is the point of the change). A `contextEscalation`
  a user added to a baseline has no override equivalent and is **not** preserved
  — a documented limitation (§4.1), surfaced by `doctor`, not silently swallowed.
- Effective-policy assembly at load (dirty shell); `classify` unchanged (pure).
- `schema.json` superset accepting both old and new formats.
- CLI: `init` writes the thin default; `doctor` drops the now-impossible
  "missing baseline" warning and gains an "override references unknown baseline"
  warning.
- Web control-plane (**W2**): a `GET /api/policy/effective` endpoint and a
  structured Policy editor — baseline rules listed with an enable toggle +
  severity dropdown, a separate section for user rules/allowlist. The
  validate-before-write + versioned-snapshot save path is unchanged.
- Replay/snapshot: old-format snapshots re-score correctly by routing the
  candidate through `normalize` + `Effective`.

**Out of scope (YAGNI / follow-up)**
- Overriding any baseline field beyond `enabled` / `severity` (no `match`/`tool`
  redefinition — that would re-introduce user-maintained regexes, the very
  staleness this removes).
- Forced disk migration writes. Load tolerates old files in-memory forever; the
  file canonicalizes naturally on the next web save. No hot-path write, ever.
- Multi-harness, per-server MCP packs, and other roadmap items.

## 2. Invariants preserved (CLAUDE.md §Architecture)

1. **Pure core, dirty shell.** All baseline/override assembly happens in `Load`
   (dirty). `classify(payload, policy) → Decision` is untouched: it receives a
   `Policy` whose `.Rules` are already the effective set, and still pulls
   `Floor()` itself. No I/O, clock, or globals enter the core.
2. **Hot path never fails open.** Assembly is deterministic and in-memory; a
   malformed file still fails `Validate` → gate falls back to the binary
   baseline (`Baseline()` + `Floor()`), never to silence.
3. **Logging/DB failures never change the verdict.** No new writes on the
   decision path. The file is only written by explicit admin actions (web save,
   `init`), off the hot path.
4. **`high` is a floor.** `overrides` can only reference **baseline** IDs and can
   only set `enabled`/`severity`. It cannot touch `Floor()`/`SelfProtectRules()`,
   which are applied in their own pass and are never in the file. A golden test
   asserts an override naming a floor ID (or trying to downgrade one) has no
   effect on the floor verdict.
5. **Self-protection stays high.** `SelfProtectRules()` unchanged, binary-owned,
   un-overridable.

## 3. Data model

### 3.1 The three rule groups (source of truth = `internal/policy/defaults.go`)

| Group | Function | Owner | Applied |
|---|---|---|---|
| Floor + self-protect | `Floor()` (incl. `SelfProtectRules()`) | binary | own pass in `classify` (unchanged) |
| **Baseline** | **`Baseline()`** (renamed from `Default().Rules`) | **binary** | assembled at load, overrides applied |
| User rules | `File.Rules` | file | assembled at load, appended |

`Baseline()` returns exactly the rules `Default()` returns today (the enabled,
non-`AlwaysHigh` seed rules). `SeedRuleIDs()` is redefined to derive from
`Baseline()` (unchanged behavior, clearer source).

### 3.2 On-disk format (canonical, thin)

```json
{
  "version": 3,
  "defaults": {},
  "overrides": {
    "sudo": { "enabled": false },
    "pkg-install-lifecycle": { "severity": "low" }
  },
  "rules": [
    { "id": "allow-…", "allow": true, "tool": ["Bash"], "match": { "raw": "…" }, "reason": "…" }
  ]
}
```

- `overrides`: object keyed by **baseline rule ID** → `{ enabled?, severity? }`,
  both optional. Absent key = use the binary's baseline verbatim.
- `rules`: **only** user-authored rules — allowlist (`allow:true`) entries and
  any custom rules the user wrote. Baselines are never listed here.

### 3.3 Go types (`internal/policy`)

```go
// Override is a user tweak to a single binary-owned baseline rule.
// Enabled is a *bool so "absent" (nil, use baseline) is distinct from
// "explicitly false". Severity "" means "unchanged".
type Override struct {
    Enabled  *bool  `json:"enabled,omitempty"`
    Severity string `json:"severity,omitempty"`
}

// File is the on-disk policy document shape.
type File struct {
    Version   int                 `json:"version"`
    Meta      map[string]string   `json:"meta,omitempty"`
    Defaults  Defaults            `json:"defaults,omitempty"`
    Overrides map[string]Override `json:"overrides,omitempty"`
    Rules     []Rule              `json:"rules"`
}
```

`Policy` (the classify-facing type) is unchanged in shape — `Load` returns a
`Policy` whose `.Rules` is the assembled effective set. `classify` never sees
`File`/`Override`.

## 4. Load pipeline

```
Load(path):
  bytes ← ReadFile(path)
  Validate(bytes)                    // schema (superset: accepts old + new)
  file  ← normalize(bytes)           // → canonical File (M1 migration in-memory)
  return file.Effective()            // → Policy{Rules: assembled}
```

### 4.1 `normalize(bytes) → File` — one function, every entry point

Accepts any historically-valid document and yields a canonical `File`:

- For each entry in the raw `rules` array:
  - **ID ∈ `Baseline()` IDs** (an old inline baseline copy): compare against the
    binary's baseline rule of that ID.
    - `enabled:false` or a differing `severity` → record into
      `overrides[id]` (**M1**: the user's edit is preserved as an override).
    - identical stock copy → **drop** (the binary now owns it).
  - **ID ∉ baseline** (allowlist / custom) → keep in `File.Rules`.
- Merge any explicit `overrides` block from the document (explicit wins over
  derived, though in practice they won't collide).

A user rule that happens to reuse a baseline ID is **not** treated as a baseline
copy when it is an allowlist entry (`allow:true`) — an allow rule is never a
baseline, so it is always kept in `File.Rules` (guards against an allowlist entry
being silently swallowed by an ID collision).

Non-`enabled`/`severity` differences in an inline baseline copy (`match`,
`reason`, `tool`, `contextEscalation`) have no override representation and are
**not** carried over — the binary's current definition wins (intended: the whole
point is that the binary owns those). This is not silent: `doctor` reads the raw
pre-`normalize` file and **warns** when an inline baseline copy carried such a
customization, so the operator knows their hand-edit was superseded (§6).

`normalize` is total and pure (no I/O): the same result whether the input is a
brand-new thin file, an old fat file, or empty. It is the single migration
authority — used by `Load`, by web save, and by replay's candidate path, so
"what load sees" always equals "what a save would write".

### 4.2 `File.Effective() → Policy`

```
Effective():
  rules ← []
  for b in Baseline():
      o ← overrides[b.ID]
      if o.Enabled == &false: continue          // disabled → omit entirely
      r ← b
      if o.Severity != "": r.Severity = o.Severity
      rules = append(rules, r)
  rules = append(rules, file.Rules...)          // user rules after baselines
  return Policy{Version, Defaults, Rules: rules}
```

`classify` then does `consider(Floor())` + `consider(pol.Rules)` exactly as
today. Override severity flows through the normal max-wins ranking; a disabled
baseline simply isn't present. Floor is untouched by any of this.

An override severity outside the enum, or naming an unknown ID, is validated at
the schema layer (enum) / ignored safely at assembly (unknown ID has no baseline
to attach to) and surfaced by `doctor` (§6).

## 5. Schema (`schema.json`)

- Add `overrides`: `object`, `additionalProperties` = `{ enabled: boolean,
  severity: <existing severity enum>, additionalProperties:false }`.
- Keep `rules` as-is (an old fat file still validates; `normalize` handles the
  rest). No hard format gate, so both shapes pass `Validate` before `normalize`.
- `version` stays the **incrementing snapshot counter**, not a format
  discriminator — format is detected structurally in `normalize`, so no branch
  keys off it. A fresh `init` starts at `1`; each web save bumps it (§7.1). The
  `"version": 3` in the §3.2 example is just an install that has saved three
  times, nothing format-specific.

## 6. CLI

- **`init`** (`internal/cli/init.go`, `seedPolicy`): when `policy.json` is
  absent, write the **thin default** — `{ "version": 1, "rules": [] }` (no
  baselines inline). An existing file is still left untouched; `Load` now
  understands the old shape, so no regenerate is needed. The `policy_versions`
  seed row records this thin document.
- **`doctor`** (`internal/cli/doctor.go`):
  - **Remove** the "missing baseline seed rules" check (impossible now —
    baselines come from the binary).
  - **Add** a check: every key in `overrides` must be a current `Baseline()` ID;
    an unknown key → `WARN policy: override references unknown baseline rule "<id>"`
    (a stale override after a rule was renamed/removed). This is the correctly-
    oriented drift check for the new model.
  - **Add** a migration-honesty check: read the raw file and warn when an inline
    baseline copy differs from the binary in a non-migratable field
    (`match`/`reason`/`tool`/`contextEscalation`) → `WARN policy: baseline "<id>"
    customization not migrated (binary definition now applies)`. Makes the
    intended §4.1 discard visible instead of silent.
  - Keep the load/validate/store/hook checks.

## 7. Web control-plane (W2)

### 7.1 API
- **New `GET /api/policy/effective`** — returns, for the editor:
  - `baselines`: each `Baseline()` rule with `{ id, reason, tool, defaultSeverity,
    override: { enabled, severity } | null }` (override reflects the current file).
  - `userRules`: the `File.Rules` (allowlist + custom), as today.
  - `versions`: the audit trail (unchanged).
- **`PUT /api/policy`** — body is the thin `File` (overrides + user rules).
  `persistPolicy` is unchanged: `Validate` → stamp version → write canonical →
  snapshot. The single write/audit invariant (document version == snapshot
  version) is preserved.
- `GET /api/policy/versions/{v}` — unchanged (raw snapshot; may be old-format,
  shown verbatim for inspection).

### 7.2 Frontend (`static/policy.mjs`)
- Replace the raw textarea with a structured panel:
  - **Baseline rules**: one row each — rule id + reason, an **enable toggle**,
    a **severity dropdown** (initialized to `defaultSeverity`, changing it
    creates an override). A row visibly marked when it carries an override.
  - **User rules / allowlist**: listed and editable (add/remove), as before.
- On save, the frontend assembles the thin `File` from panel state and `PUT`s it.
- Keep a collapsed "raw JSON" advanced view as an escape hatch (reads the same
  `File`); it is secondary, not the primary surface.
- `style.css`: minimal additions for the rows/toggles; no new dependency, no
  build step (consistent with the existing no-build `.mjs` modules).

## 8. Replay / snapshots

- `cli/replay` already receives a `policy.Policy` loaded via `policy.Load` →
  now already the effective set. No change needed beyond the new `Load`.
- Web replay's candidate path (`closeloop.go` `parsePolicy`) routes bytes through
  `normalize` + `Effective` so an old-format candidate (or an old snapshot)
  re-scores against the **current** binary baselines — the correct semantics:
  "how would this policy behave on today's engine".
- Old `policy_versions` snapshots (fat, inline baselines) are re-scored the same
  way; no data migration of stored snapshots is performed. The same §4.1 caveat
  applies: a snapshot's inline `enabled`/`severity` edits re-derive as overrides,
  but a `match`/`contextEscalation` edit in a snapshot is not preserved — it
  re-scores against the current binary baseline. This is consistent with the load
  path (same `normalize`), so it is a property, not a separate defect.
- The **CLI** `replay --version N` path (`cmd/argus/main.go`) must also route the
  snapshot bytes through `EffectiveFromBytes`, not a bare `json.Unmarshal` into
  `Policy` — otherwise a thin snapshot re-scores with no baselines.

## 9. Testing (TDD, table-driven; CLAUDE.md §Testing)

- `Baseline()` / `SeedRuleIDs()`: IDs match today's `Default()` seed set.
- `applyOverrides` / `Effective`: severity override changes the rank; `enabled:
  false` omits the rule; an override for an unknown ID is a no-op; a user rule is
  appended after baselines.
- `normalize` (golden): (a) old fat file with a disabled + a severity-edited
  baseline + an allowlist → canonical `File` with two derived overrides and the
  allowlist retained, stock copies dropped; (b) a new thin file round-trips
  unchanged; (c) empty/`{}` → empty `File`.
- **Invariant golden**: an `overrides` entry naming a floor ID (e.g.
  `pipe-to-shell`) or trying to downgrade a baseline that a floor also covers
  does **not** lower the floor verdict — floor still denies. Self-protect still
  fires regardless of overrides.
- `classify` regression: the full existing golden + evasion corpus stays green
  unchanged (proof the assembled policy is behavior-equivalent to the old
  inline-baseline policy for an un-overridden file).
- `gate` integration: an old-format `policy.json` on disk classifies identically
  to a fresh thin one (migration parity), and a brand-new binary baseline is
  present without any file edit.
- `doctor`: unknown-override-ID → WARN; a clean thin file → all PASS.
- web: `GET /api/policy/effective` shape; save round-trip writes canonical thin
  JSON and bumps a version.

## 10. Build order (for the implementation plan)

1. **G-1 — engine/model:** `Override`/`File` types, `Baseline()`, `normalize`,
   `File.Effective()`, new `Load`, `schema.json`, gate + replay wiring. The
   spine; everything else consumes it.
2. **G-2 — CLI:** `init` thin default; `doctor` check swap.
3. **G-3 — web (W2):** `/api/policy/effective`, structured `policy.mjs` editor,
   `style.css`. Heaviest frontend work, isolated last.

Each stage keeps `go build ./... && go test ./...` green and is independently
committable.

## 11. Open items for the maintainer

1. Confirm the thin `init` default is `{ "version": 1, "rules": [] }` (no seeded
   `overrides`), i.e. a fresh install starts with zero overrides and the full
   binary baseline.
2. Confirm the raw-JSON advanced view is retained in the web editor (escape
   hatch) rather than removed outright.
