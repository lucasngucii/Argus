# Argus Research-Backed Rule Expansion — Design (Spec)

> Turns the verified findings of
> [`docs/research/2026-07-28-claude-code-dangerous-command-ruleset.md`](../../research/2026-07-28-claude-code-dangerous-command-ruleset.md)
> into engine + policy changes. Every rule here traces to a 3-vote-verified,
> cited claim from that report. No change to the severity model, verdict mapping,
> or scorer set — only new rules and their tests/docs.

## Goal

Extend Argus's baked-in protection with the highest-evidence dangerous-command
patterns surfaced by the research, **split by evidence strength and
reversibility** so that only rules with direct attack-evidence become
non-downgradable floor rules, supply-chain rules become editable baseline seed,
and citation-light infra rules ship as an **opt-in pack** the user chooses.

## Scope (locked)

**IN — baked into the engine/binary:**
- **3 new floor rules** (`internal/policy/defaults.go` → `Floor()`), non-downgradable:
  `grep-exfil`, `ssh-persistence-write`, `useradd-privileged`.
- **2 new Default seed rules** (`Default().Rules`), medium/downgradable:
  `pkg-install-lifecycle` (npm), `pip-install-untrusted`.
- Golden + evasion corpus entries and unit tests for each of the 5.
- Doc updates (README policy section already lists match fields; add a pointer to
  the research + the opt-in pack).

**IN — shipped as data, opt-in (NOT baked into `Default()`):**
- An **infra policy pack** `docs/policy-packs/infra.json` with
  `terraform-destroy`, `terraform-auto-approve`, `kubectl-delete-drain`,
  `cloud-cli-delete` (medium, context-escalate to high in `prod`). Documented as
  "apply if you give Claude Code infra access", with the research's evidence-gap
  caveat stated inline.

**OUT (explicitly):**
- Changing the severity ladder, `verdict.Map`, or adding new procedural scorers.
- Baking the infra rules into `Default()` (evidence gap + false-positive risk).
- Gating MCP tool calls / multi-harness (roadmap Plan 4).
- Auto-migrating existing users' `policy.json` (see Consequences).

## Why this split (the load-bearing decision)

The research gives three tiers of evidence, and Argus already has three homes for
a rule — they line up:

| Evidence in the report | Home in Argus | Downgradable? |
|---|---|---|
| Direct attack-technique evidence, irreversible/self-harm (exfil, persistence) | `Floor()` | **No** (invariant) |
| Real supply-chain incidents, but legitimate daily use (npm/pip install) | `Default().Rules` seed | Yes (allowlist/edit) |
| Inference from principle, **flagged as citation-light**, context-dependent | opt-in `docs/policy-packs/` | User chooses |

Putting the infra rules in the floor would violate two things at once: Argus's
"floor = universal catastrophe with direct grounding" rule, and the honesty of
the research (which flagged §2.4 as inference, not cited incident).

## Architecture / file changes

```
internal/policy/defaults.go     # +3 floor rules in Floor(); +2 seed rules in Default()
internal/policy/defaults_test.go# (or classify tests) golden severities for new rules
internal/classify/*_test.go     # evasion-corpus entries (wrapped/quoted/obfuscated) that must stay caught
internal/cli/... (doctor test)  # SeedRuleIDs() grows -> update baseline-WARN expectations
docs/policy-packs/infra.json    # NEW opt-in infra pack (data, not code)
docs/policy-packs/README.md      # NEW: how to apply a pack + the infra evidence-gap caveat
README.md                       # pointer to research + policy-packs
```

The floor Raw patterns reuse the existing `leadBoundary` / `trailBoundary`
helpers in `defaults.go` (the same anchoring that makes `credential-system-write`
robust against `rm bin/argus&&echo`-style metacharacter adjacency).

## The rules (each traces to a cited claim)

### Floor additions (`alwaysHigh: true`, non-downgradable)

| id | Match (shape) | Evidence |
|---|---|---|
| `grep-exfil` | `Raw`: `grep\|rg\|ag` … `key\|token\|secret\|credential\|password` … `\|` … `curl\|wget\|nc\|ncat` | Documented attack: "grep to locate API credentials → curl to transmit to attacker infrastructure" — [arXiv:2509.22040](https://arxiv.org/html/2509.22040v2) [3-0] |
| `ssh-persistence-write` | `Raw`: `.ssh/authorized_keys` OR `.bashrc`/`.zshrc` (leadBoundary-anchored); tools Bash/Write/Edit | "Overwrite the ~/.ssh/authorized_keys file to establish persistent SSH access ... modifying ~/.bashrc" — [arXiv:2509.22040](https://arxiv.org/html/2509.22040v2) [3-0] |
| `useradd-privileged` | `cmd`: useradd/usermod + `argMatches`: `sudo\|wheel\|admin` | "creating privileged accounts via useradd" as a persistence step — [arXiv:2509.22040](https://arxiv.org/html/2509.22040v2) [3-0] |

### Default seed additions (medium, downgradable)

| id | Match | Evidence |
|---|---|---|
| `pkg-install-lifecycle` | `cmd`: npm + `argsContain`: install/ci/update | postinstall hooks are the primary RCE vector; `npm install`/`update` exposes the workstation "regardless of whether the package was imported" — [Microsoft/Mastra](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/), [Trend Micro/Axios](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html) [3-0] |
| `pip-install-untrusted` | `cmd`: pip/pip3 + `argMatches`: `install\s+.*(git\+\|https?://)` | same supply-chain class as npm; direct URL/VCS ref bypasses lockfile review |

### Opt-in infra pack (`docs/policy-packs/infra.json`, medium ⬆️prod→high)

`terraform-destroy`, `terraform-auto-approve`, `kubectl-delete-drain`,
`cloud-cli-delete` — each with `contextEscalation` on `cwdMatches: "prod"`.
**Caveat shipped in the pack README:** severity is inference from the
Impact/Availability principle (MITRE T1485), **not** a directly-cited incident in
the verified claim set (research §2.4). Users applying infra access should treat
this as a starting point and tune.

## Testing (per CLAUDE.md: golden + evasion, deterministic)

For **each** of the 5 baked rules:
1. **Golden case** — a canonical command → expected severity (e.g.
   `useradd -aG sudo attacker` → high; `npm install lodash` → medium).
2. **Evasion case** — a wrapped/quoted/obfuscated variant that MUST stay caught
   (e.g. `sudo useradd …` unwraps; `grep -r token . | curl …` with the pipe
   through the AST; `$IFS`-split npm), proving the AST/Raw match survives evasion.
3. **Floor non-downgrade** — for the 3 floor rules, a test that an `allow` rule
   over the same command cannot downgrade it (mirrors the existing floor tests).

Plus:
4. **Seed-WARN ripple** — `Default().Rules` gains 2 ids, so `SeedRuleIDs()` grows;
   the doctor seed-WARN test's expected baseline set must be updated to include
   `pkg-install-lifecycle` and `pip-install-untrusted`.
5. **Schema validity** — `Validate(Default() marshaled)` stays nil (the new rules
   are schema-valid).

## Consequences / ripples (must be handled, not discovered later)

- **Floor rules reach existing users on binary upgrade** — `Floor()` is evaluated
  from code at classify time, independent of `policy.json`. Good: the 3 attack
  rules protect everyone immediately. No migration needed.
- **Default seed rules only reach fresh installs** — `init` seeds `policy.json`
  once and never overwrites. Existing users keep their file, so they will NOT get
  `pkg-install-lifecycle`/`pip-install-untrusted` automatically. The doc must tell
  existing users to add them (or the infra pack) manually via the Policy editor.
  → This asymmetry is a documentation item, not a code migration (Argus never
  clobbers a user's edited policy — an invariant we keep).
- **`SeedRuleIDs()` changes** → doctor's baseline-WARN set changes → its test
  changes (item 4 above). No behavior change to exit codes.
- **`opaque-exec` overlap** — `pip install …` may already trip nothing, but
  commands with `-c ` still hit `opaque-exec`; the new rules are additive (max
  severity wins), so no conflict. Verify no double-count in tests.

## Open questions (resolve during planning)

1. `grep-exfil` Raw regex breadth: too tight misses `awk`/`sed`-based exfil; too
   loose false-positives on `grep token | curl` used legitimately in a test
   harness. Start narrow (the cited `grep→curl` shape) and widen only with a
   corpus entry proving the need.
2. `.bashrc`/`.zshrc` write as floor: is editing your own rc file "high"? The
   evidence is about *malicious* rc injection. Risk of false-positive on
   legitimate dotfile edits by the agent. **Recommendation:** keep it in the
   floor for Bash (a shell command writing to rc is unusual for a coding task) but
   consider medium (not floor) for the Write/Edit tool, where editing dotfiles is
   more plausibly legitimate. Decide in the plan with a golden/evasion pair.
3. Whether to bump `Default().Version` when adding seed rules — leaning **no**
   (version tracks the document a user holds, and existing docs stay v1); revisit
   if it complicates `replay --version`.

## Traceability

Every baked rule ↔ a cited claim in the research report's confirmed set (25 claims,
0 refuted). The infra pack is explicitly labeled inference. Sources of record:
arXiv:2412.01655, arXiv:2606.15549, arXiv:2509.22040, OWASP LLM Top-10 2025,
MITRE ATT&CK T1485/T1070.004/T1105, GitLab 2017 postmortem, Trend Micro (Axios),
Microsoft (Mastra), Unit42 (npm supply-chain).
