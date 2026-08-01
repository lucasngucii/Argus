# Codex hook contract — verification note

**Status:** docs-grounded verification only. **No live `codex` CLI was available in this
environment**, so this note is built from primary-source documentation and GitHub
issues/PRs (each item cites its source). Items that can only be settled by running a real
`codex` binary and capturing its actual behavior/output are marked **PENDING (needs live
`codex` CLI)** below. Do not write Codex adapter code that depends on a PENDING item without
re-confirming it against a pinned `codex --version` first.

**`codex --version` at time of writing:** PENDING (needs live `codex` CLI) — no binary was
available to record this. All facts below are sourced from documentation and issues current
as of the 2026 sources cited; they should be re-checked against whatever version is actually
targeted before the adapter ships.

---

## A. Block signals

**Finding:** Exit code 2 with a stderr reason blocks the tool call. A `hookSpecificOutput`
deny JSON (structured `permissionDecision: "deny"` payload) also blocks, independent of the
exit-2 path.

**Implication for the plan:** the plan's deny path emits both JSON *and* exit 2 — exit-2-blocks
is the load-bearing fact, and it is confirmed by the docs. The JSON path is corroborating, not
required.

**Source:** https://learn.chatgpt.com/docs/hooks (official; this is the redirect target of
https://developers.openai.com/codex/hooks) — hook exit-code/stderr blocking semantics.
Real-world hook implementation for cross-check: https://github.com/falcosecurity/prempti/blob/main/hooks/codex/README.md

**Live capture needed:** PENDING (needs live `codex` CLI) — to confirm the exact stderr
formatting Codex surfaces to the user/model when a hook exits 2, and to confirm the two
signals (exit 2, deny JSON) are equivalent rather than the JSON being additive/informational
only.

---

## B. Allow shape

**Finding:** Empty `{}` / empty stdout with exit code 0 = allow. Codex **ignores** any allow
payload it is given — an explicit "allow" body is not required and is reportedly not honored
either way. `updatedInput` is **explicitly rejected**: do not emit it.

**Correction to the v1 plan:** the v1 assumption that a populated allow body or
`suppressOutput` "breaks"/"marks the run failed" is **unsubstantiated** by any source found.
The real reason to emit `{}` is simply that Codex ignores the allow payload — there is no
evidence it treats a non-empty allow body as an error. Do not carry the "breaks the run" claim
forward without a live repro.

**Source:** https://learn.chatgpt.com/docs/hooks ; https://github.com/openai/codex/issues/18491

**Live capture needed:** PENDING (needs live `codex` CLI) — to confirm empirically that a
non-empty allow body does not cause any observable difference (e.g. warning, run failure) and
that `updatedInput` is silently dropped rather than causing an error.

---

## C. `ask` rejection

**Finding:** Codex's hook contract is **deny-only**. It parses `permissionDecision` values
other than `"deny"` (including `"ask"` and `"allow"`) but does not honor them as anything but
"not deny" — the tool call proceeds. There is no interactive ask/confirmation flow driven by
hook output.

**Implication for the plan:** this justifies collapsing `Shape(codex, "ask")` → `"deny"` in
the adapter — since Codex has no ask semantics, downgrading an Argus `ask` verdict to `allow`
on Codex would fail open, whereas mapping it to `deny` is the only fail-closed choice
available in Codex's vocabulary.

**Source:** https://learn.chatgpt.com/docs/hooks

**Live capture needed:** PENDING (needs live `codex` CLI) — to directly observe that an
`ask`-shaped hook response results in the command running rather than any pause/prompt.

---

## D. Payload + tool name

**Finding:** Codex's PreToolUse stdin payload is snake_case and is a superset of Argus's
`hook.Payload` fields: `session_id`, `turn_id`, `transcript_path`, `cwd`, `hook_event_name`,
`permission_mode`, `tool_name`, `tool_use_id`, `tool_input.command`. For the shell tool,
`tool_name` is **`"Bash"`** (capitalized). This value was historically hardcoded and became
handler-supplied as of Codex 0.123, but the shell handler still supplies `"Bash"` — the string
value observed by callers does not change across that refactor.

**Source:** https://github.com/openai/codex/pull/18391 (0.123 handler-supplied tool_name);
https://github.com/openai/codex/issues/18491

**Live capture needed:** PENDING (needs live `codex` CLI) — a real captured PreToolUse JSON
payload for a shell command has not been obtained. Before shipping, capture one and confirm
(a) the field set matches exactly what's listed above, (b) `hook.Parse` on Argus's side
decodes it correctly, and (c) `Subject()` derived from `tool_input.command` matches the actual
command string.

---

## E. Feature flag — name, section, scope, default

**Finding:** The canonical config key is **`[features].hooks`** in `config.toml`.
`codex_hooks` is a **deprecated but still-working alias**. Only **user-level**
`~/.codex/config.toml` is reliable for enabling hooks — repo-local `.codex/config.toml` hook
configuration silently fails in interactive mode (does not error, just doesn't take effect).

**Source:** https://github.com/openai/codex/issues/22148 (canonical key / deprecated alias);
https://github.com/openai/codex/issues/17532 (repo-local config silently fails interactively);
https://learn.chatgpt.com/docs/hooks

**Live capture needed:**
- Whether the target version **defaults `[features].hooks` on** — PENDING (needs live `codex`
  CLI), version-dependent and not stated in the sources reviewed.
- Whether the config directory resolves to `~/.codex`, or is overridable via `CODEX_HOME` /
  `XDG_CONFIG_HOME` — PENDING (needs live `codex` CLI) to pin definitively for the target
  version; sources reference `CODEX_HOME` informally but do not give an authoritative
  precedence order.

---

## F. `apply_patch`

**Finding:** `apply_patch` fires PreToolUse only on Codex **≥ v0.123** (introduced in PR
#18391). On earlier versions it does not fire at all.

**Implication for the plan:** safe to scope `apply_patch` OUT of the first-cut matcher
(Bash-only), with a follow-up task to add it once the adapter targets ≥0.123 and the matcher
is extended. This avoids both false coverage claims on older versions and unnecessary
complexity in the first cut.

**Source:** https://github.com/openai/codex/pull/18391 ; https://github.com/openai/codex/issues/18491

**Live capture needed:** none required to accept the scoping decision — version-gating is
sufficient. A live capture of the `apply_patch` payload shape is only needed when the
follow-up task to add `apply_patch` coverage is picked up.

---

## G. Hook TRUST (critical — silent no-op path)

**Finding:** Even after a hook is wired (present in `hooks.json`/`[hooks]`) and the
`[features].hooks` flag is on, Codex still requires the hook to be explicitly **trusted**
before it will execute — via the interactive `/hooks` command, or by passing
`--dangerously-bypass-hook-trust` at launch. An untrusted hook is **silently inert**: it does
not run, and there is no error surfaced. This state is not detectable from disk (the hook file
and config can look perfectly correct while the hook never fires), so `doctor`/`init` cannot
verify it by inspecting files alone.

There is also a known regression: `--dangerously-bypass-hook-trust` was itself ignored in the
TUI across Codex 0.131–0.133 (bug), fixed by PR #24317.

**Implication for the plan:** this must be surfaced explicitly in `init` output (tell the user
they still need to run `/hooks` or pass the bypass flag) and as a `doctor` WARN — `doctor`
cannot confirm trust state from disk, so the warning should be unconditional/informational
rather than a disk-based check, and should call out the 0.131–0.133 bypass-flag bug if the
detected version falls in that range.

**Source:** https://learn.chatgpt.com/docs/hooks ; bug history:
https://github.com/openai/codex/issues/24093 (bypass flag ignored in TUI 0.131–0.133, fixed by
PR #24317)

**Live capture needed:** PENDING (needs live `codex` CLI) — to confirm the exact `/hooks` UX
and to confirm whether `--dangerously-bypass-hook-trust` works correctly outside the
0.131–0.133 window (i.e. on whatever version is ultimately targeted).

---

## H. MCP / coverage truth

**Finding:** PreToolUse fires for exactly **four** tool classes: `shell` (Bash),
`unified_exec`, `apply_patch` (≥0.123), and `mcp` (as `mcp__server__tool`). All other local
tools and all hosted tools (e.g. web search) do **not** fire PreToolUse. Note:
`read_file`/`grep` are not real Codex tool identifiers at all — they should not appear in any
coverage statement. The correct boundary to state is: "only shell/unified_exec/apply_patch/mcp
fire PreToolUse; nothing else does."

**Implication for the plan:** this sets the exact wording for Task 8's coverage
documentation — it should enumerate these four classes rather than making a vaguer claim
about "most tools" or referencing tool names (`read_file`, `grep`) that don't exist in Codex.

**Source:** https://github.com/openai/codex/issues/20204 ; https://learn.chatgpt.com/docs/hooks

**Live capture needed:** none required to accept this boundary statement — it is corroborated
by both the issue and the official docs. A live capture would only add confirmation, not new
information.

---

## I. Windows

**Finding:** Early Codex builds did not run hooks on Windows at all.

**Live capture needed:** PENDING (needs live `codex` CLI) — whether this is still true for the
target version is unconfirmed; no source pins a version where Windows hook support was fixed.
This must be checked on the actual target version before claiming Windows support (or lack
thereof) in adapter documentation.

**Source:** issue references cited in the plan review; no specific fix-version citation was
found during this pass — treat as PENDING rather than resolved.

---

## J. `unified_exec` (matcher under-coverage — important)

**Finding:** Codex fires PreToolUse for `unified_exec`, a shell-execution path distinct from
the `shell`/`Bash` tool. Its `tool_name` value is **not confirmed** to be `"Bash"` — no source
reviewed states what `tool_name` `unified_exec` invocations actually carry.

**Risk to the plan:** if `unified_exec`'s `tool_name` is not `"Bash"`, a Bash-only matcher
(`^Bash$`) will **silently miss** commands routed through `unified_exec` — they will run
completely ungated by Argus, with no error or warning. This is under-coverage of a *matched*
event category, not a fail-open of something Argus already inspected, but the practical effect
(a dangerous command running unchecked) is the same as fail-open from the user's perspective.

**Required action before Task 6 (matcher):** capture a real `unified_exec`-routed command's
PreToolUse payload and read its `tool_name` field directly.
- If `tool_name == "Bash"`, no matcher change needed.
- If it differs, the matcher must widen to something like `^(Bash|unified_exec)$` (adjust to
  the actual observed value) before the adapter can claim to cover all shell execution.

**Source:** https://github.com/openai/codex/issues/20204

**Live capture needed:** PENDING (needs live `codex` CLI) — this is the single highest-priority
live capture blocking Task 6; the matcher must not be written as Bash-only until this is
resolved, or it must ship with an explicit documented gap and a tracking follow-up.

---

## K. Config precedence

**Finding:** Both `~/.codex/hooks.json` and an inline `[hooks]` block in `config.toml` can
define hooks. No source reviewed states an authoritative precedence order between the two, nor
whether Argus's `Wire` step (which writes `hooks.json`) could be silently shadowed by an
existing inline `[hooks]` block in `config.toml`.

**Risk to the plan:** if `[hooks]` in `config.toml` takes precedence over `hooks.json` (or
vice versa in a way `Wire` doesn't expect), `Wire` could write a config file that Codex never
actually reads, another silent-no-op failure mode alongside trust (item G).

**Live capture needed:** PENDING (needs live `codex` CLI) — must construct a test case with
both `hooks.json` and inline `[hooks]` present simultaneously and observe which one Codex
honors, before `Wire`/`doctor` can make any claim about `hooks.json` being authoritative.

**Source:** no authoritative source found for precedence; flagged from the plan review itself
pending live verification.

---

## Summary — items blocking further Codex adapter work

The following PENDING items should be resolved with a live `codex` CLI **before** the
corresponding downstream task proceeds:

| Item | Blocks | Reason |
|---|---|---|
| Version pin (top of note) | All tasks | Every fact below is version-sensitive |
| D — real payload capture | Task on `hook.Parse`/payload decoding | Need ground-truth JSON shape |
| E — flag default, config dir | `init`/`doctor` flag-setup logic | Determines whether Argus must set the flag itself |
| G — trust UX detail | `init` output wording, `doctor` WARN wording | Need exact `/hooks` flow and bypass-flag version behavior |
| I — Windows | Any Windows-specific documentation/support claim | Unconfirmed for target version |
| **J — `unified_exec` tool_name** | **Task 6 (matcher)** | **Highest priority — determines matcher correctness, risk of ungated commands** |
| K — hooks.json vs `[hooks]` precedence | `Wire`/`doctor` | Risk of `Wire` writing a file Codex ignores |

Items A, B, C, F, H are corroborated by at least one authoritative doc/issue source each and
are safe to design against, though a live capture would still strengthen confidence on A/B/C.
