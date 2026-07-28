# Argus Research-Backed Rule Expansion — Design (Spec, rev 2)

> Turns the verified findings of
> [`docs/research/2026-07-28-claude-code-dangerous-command-ruleset.md`](../../research/2026-07-28-claude-code-dangerous-command-ruleset.md)
> into engine + policy changes. Every rule traces to a 3-vote-verified cited claim.
> **Rev 2** — revised after two independent adversarial reviews (technical
> correctness + evidence/false-positive). Changelog at end.

## Goal

Extend Argus's baseline protection with the highest-evidence dangerous-command
patterns from the research, **as ask-a-human (`medium`) seed rules plus an
opt-in pack** — after review, none of the candidates justified a new
non-downgradable floor rule. No change to the severity model, verdict map, or
scorer set.

## Key finding from review: no new floor rules

The research's strongest floor candidates did **not** survive scrutiny as floor
rules:
- `ssh-authorized-keys-write` — **redundant**: the existing floor rule
  `credential-system-write` (`defaults.go`) already floors `~/.ssh/authorized_keys`
  and `~/.ssh/id_*` for Bash/Write/Edit. Adding it is dead code.
- `grep→curl` exfil — a **keyword-intent heuristic**, not a structural
  catastrophe. Flooring it makes false positives (a legit `grep secret_config |
  curl $WEBHOOK`) non-downgradable, while a trivial intermediate pipe stage
  (`grep secret f | base64 | curl`) evades it. Floor tier is reserved for
  structurally-unambiguous catastrophes; this is the textbook ask-a-human case.
- `useradd`-privileged — legitimate in Dockerfiles/provisioning; flooring denies
  those with no recourse.

**Conclusion (honest):** Argus's *existing* floor already covers the unambiguous
catastrophes the research names (disk wipe, fork bomb, pipe-to-shell, destructive
SQL, credential/system writes). The research's *added* value is entirely in the
**`medium` (ask)** tier — supply-chain, exfil-shaped pipelines, privileged-account
creation, rc-file injection — plus a context-escalated infra pack.

## Scope (locked, rev 2)

**IN — baked into `Default().Rules` as `medium` seed rules** (downgradable; reach
fresh installs only, since `init` never overwrites an edited `policy.json`):
- `grep-exfil` — credential search piped to a network sink.
- `useradd-privileged` — `useradd`/`usermod`/`adduser` naming a `sudo`/`wheel` group.
- `pkg-install-lifecycle` — `npm install`/`i`/`ci`/`update` (supply-chain RCE).
- `rc-file-inject` — a shell **redirect** (`>`/`>>`) into `~/.bashrc`/`~/.zshrc`.

**IN — opt-in pack `docs/policy-packs/infra.json`** (medium, context-escalate to
high in `prod`): `terraform-destroy`, `terraform-auto-approve`,
`kubectl-delete-drain`, `cloud-cli-delete`. Pack README documents `pip install`
from a URL/VCS ref as an *optional* rule (inference, no cited incident).

**OUT (explicitly):**
- Any **new floor rule** (see finding above — none justified).
- `ssh-authorized-keys-write` (redundant with `credential-system-write`).
- `pip-install-untrusted` **baked** (inference, no cited incident; documented in
  the pack README instead, matching the evidence discipline applied to infra).
- Baking the infra rules into `Default()` (evidence gap + false-positive risk).
- Changing the severity ladder / `verdict.Map` / adding scorers.
- Auto-migrating existing users' `policy.json` (Argus never clobbers it).
- Gating MCP / multi-harness (roadmap Plan 4).

## Rules (each traces to a cited claim)

| id | Match (shape) | Severity | Evidence |
|---|---|---|---|
| `grep-exfil` | `Raw`: `(grep\|rg\|ag)` … `key\|token\|secret\|credential\|password` … `\|` … `curl\|wget\|nc\|ncat` | **medium** | grep→curl credential exfil is a documented attack — [arXiv:2509.22040](https://arxiv.org/html/2509.22040v2) [3-0] |
| `useradd-privileged` | `cmd`: useradd/usermod/adduser + `argsContain`: sudo/wheel | **medium** | privileged-account creation is a documented persistence step — [arXiv:2509.22040](https://arxiv.org/html/2509.22040v2) [3-0] |
| `pkg-install-lifecycle` | `cmd`: npm + `argMatches`: `^(install\|i\|ci\|update)\b` | **medium** | postinstall hooks are the primary RCE vector; install exposes the host "regardless of whether the package was imported" — [Microsoft/Mastra](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/), [Trend Micro/Axios](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html) [3-0] |
| `rc-file-inject` | `Raw`: redirect (`>`/`>>`) into `.bashrc`/`.zshrc` | **medium** | overwriting/appending shell rc for persistence — [arXiv:2509.22040](https://arxiv.org/html/2509.22040v2) [3-0] |

Design notes baked in from review:
- **`grep-exfil` uses `argsContain`-free Raw** and is `medium` — an ambiguous
  exfil-shaped pipeline is asked, not silently denied.
- **`pkg-install-lifecycle` uses `argMatches` anchored `^(install|i|ci|update)\b`**
  (not `argsContain`) so it catches `npm i` and does NOT fire on `npm run ci`.
  RE2 has no lookahead, so `--ignore-scripts` cannot be excluded in-regex; the
  rule's `reason` states this and the safe path is a one-line user allowlist.
- **`useradd-privileged` uses exact-token `argsContain: ["sudo","wheel"]`** (not a
  regex on "admin") so `useradd admin` (a user *named* admin) does NOT fire.
- **`rc-file-inject` matches only a shell redirect** into rc (Bash tool), so
  reading (`cat ~/.bashrc`) and Write/Edit of dotfiles do NOT fire.

## Architecture / file changes

```
internal/policy/defaults.go        # +4 medium rules in Default().Rules (NO Floor() changes)
internal/classify/classify_test.go # +golden/evasion tests per rule
internal/cli/testdata/{golden,evasion}.jsonl # +positive + near-miss corpus lines
docs/policy-packs/infra.json       # NEW opt-in infra pack
docs/policy-packs/README.md         # NEW how-to + evidence-gap caveat + optional pip rule
README.md                          # pointer to research + policy-packs
```

No `Floor()` change → **no ripple to existing floor/self-protect tests**. Adding
4 medium seed rules grows `SeedRuleIDs()`, but its test builds the expected set
**dynamically** from `Default().Rules` (verified by review) and the doctor
seed-WARN test only checks the `sudo` substring — **no test edits required** for
the ripple.

## Testing (per CLAUDE.md: golden + evasion, deterministic)

Per baked rule: (1) a golden positive (`sev(cmd,cwd)` → medium), (2) a near-miss
that must NOT fire (stays safe), (3) a wrapped/obfuscated evasion variant that
stays caught, and (4) a corpus line in `golden.jsonl` (near-miss) + `evasion.jsonl`
(positive). Plus: `Validate(Default() marshaled)` stays nil; the infra pack has
its own schema-validity test.

## Consequences

- **Medium seed rules reach fresh installs only** — existing users keep their
  `policy.json`; they add these via the web Policy editor (documented). Not a code
  migration (Argus never clobbers an edited policy — invariant kept).
- **No floor change** → existing users' catastrophe protection is unchanged; this
  expansion is purely additive baseline coverage for fresh installs + an opt-in
  pack.

## Known gaps (accepted for v1, documented)

- `pkg-install-lifecycle` npm-only (no `yarn`/`pnpm`/`bun`); `--ignore-scripts`
  still asks (RE2 no-lookahead) — widen with corpus evidence later.
- `useradd-privileged` misses comma-group `-aG sudo,docker` (one token) and
  `gpasswd -a`; `grep-exfil` misses non-adjacent sinks (`| base64 | curl`) and
  `cat ~/.aws/credentials | curl` — starting narrow, widen only with a corpus
  entry proving the need.
- Infra pack `cloud-cli-delete` misses `aws … terminate-instances` / `s3 rb`;
  `-auto-approve=true` (exact-token) — noted in the pack README.

## Changelog (rev 1 → rev 2), from two adversarial reviews

**BLOCKING fixed:** dropped `ssh-authorized-keys-write` (redundant with existing
`credential-system-write`; its TDD red-step was impossible). **Design fixed:**
`grep-exfil` and `useradd-privileged` demoted from floor to `medium` (keyword
heuristic / legitimate uses → false positives shouldn't be non-downgradable);
`pkg-install-lifecycle` switched to anchored `argMatches` to catch `npm i` and
exclude `npm run ci`; `pip-install-untrusted` moved out of baked seed to the
opt-in pack (inference, no cited incident); added `rc-file-inject` as `medium`
(a cited [3-0] technique that rev 1 dropped entirely); `useradd` FP on a user
*named* `admin` fixed via exact-token `argsContain`. **Nits:** removed the
false "SeedRuleIDs ripple" step (test is dynamic); infra-pack `cloud-cli-delete`
/ `-auto-approve` gaps documented.
