# @agrus/argus

**A local-first governance and observability gate for AI coding agents.**

Argus sits in front of every shell command and file write an AI coding agent
(Claude Code today) tries to run, classifies it by severity, and decides
**allow / ask / deny** — then records every decision to a local database so you
can see, explain, and tune what your agents are doing.

This package ships the prebuilt native `argus` binary; installing it puts
`argus` on your PATH (no Go toolchain needed).

## Install

```bash
npm install -g @agrus/argus
argus init      # creates ~/.argus/, seeds policy.json, wires the Claude Code
                # PreToolUse hook into ~/.claude/settings.json (idempotent)
argus doctor    # verify the install is wired and healthy
```

That's it — Claude Code now routes Bash/Write/Edit tool calls through Argus.

Supported prebuilt platforms: **macOS** and **Linux** (arm64 + x64). On any
other platform, install fails over to a pointer to the release archives or
`go install github.com/lucasngucii/argus/cmd/argus@latest`.

## Use

```bash
argus explain "sudo rm -rf /"   # dry-run: severity, firing rule, verdict, AST facts
argus stats                     # decision digest (counts, denies, recent high/medium)
argus serve                     # local web control-plane (loopback): live tail,
                                # stats, explain, policy editor, replay simulator
```

## Why it's different

- **A severity model, not a binary** — `safe` / `low` / `medium` / `high`.
- **AST-based, not regex** — commands are parsed with a real shell parser
  (`mvdan/sh`), so obfuscation (`X=rm; $X -rf /`, `… | base64 -d | sh`) is seen
  and **escalated**, never matched blindly.
- **Fail-closed** — on any error touching a dangerous verb, it escalates; it is
  never silently allowed.
- **A non-bypassable `high` floor** — disk wipes, fork bombs, pipe-to-shell,
  destructive SQL, recursive-rm of `/`/`~`/system dirs are denied in every mode
  and can't be downgraded by policy or an allow-list.
- **Self-protection** — an agent can't disarm the gate or touch credential/system
  paths.
- **A local decision store** — SQLite under `~/.argus/`, enabling **replay**
  (re-score history against a candidate policy), **explain**, and history mining.
- **Local-first** — no SaaS, no network calls, no telemetry.

## Uninstall

```bash
npm uninstall -g @agrus/argus
# then remove the "argus gate" entry from ~/.claude/settings.json to unwire the hook
```

Full docs, policy/rule reference, and design: <https://github.com/lucasngucii/Argus>.
MIT licensed.
