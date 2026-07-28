# @agrus/argus

**A permission gate for AI coding agents.** Argus classifies every shell command
and file write Claude Code tries to run as `safe / low / medium / high` and
decides **allow / ask / deny**, logging each decision locally.

This package installs the prebuilt native `argus` binary on your PATH — no Go
toolchain needed.

## Install

```bash
npm install -g @agrus/argus
argus init      # set up ~/.argus/ and wire the Claude Code hook
argus doctor    # verify
```

Claude Code now routes Bash/Write/Edit calls through Argus. Prebuilt for macOS &
Linux (arm64/x64).

## Use

```bash
argus explain "sudo rm -rf /"   # why a command classifies as it does
argus stats                     # decision digest
argus serve                     # local web UI: live tail, policy editor, replay
```

## Why

- **Severity, not yes/no** — a scratch `rm` isn't treated like wiping `/`.
- **Parsed, not regexed** — a real shell parser catches obfuscation instead of
  being bypassed by it.
- **Non-bypassable `high` floor** — disk wipe, `curl … | sh`, `rm -rf /`,
  credential writes are always denied.
- **Fails closed. Local-first** — no network, no telemetry.

Full docs: <https://github.com/lucasngucii/Argus> · MIT.
