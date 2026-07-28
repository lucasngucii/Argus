# @agrus/argus

> **Your AI coding agent has a shell.** `rm -rf /`, `curl … | sh`, a force-push
> to `main` — it can run all of them. Argus classifies every command and file
> write before it happens and decides **allow / ask / deny**.

This package installs the prebuilt native `argus` binary on your PATH — no Go
toolchain needed.

## Install

```bash
npm install -g @agrus/argus
argus init      # set up ~/.argus/ and wire the Claude Code hook
argus doctor    # confirm it's healthy
```

Claude Code now routes Bash/Write/Edit tool calls through Argus. Prebuilt for
macOS & Linux (arm64/x64).

## Use

```bash
argus explain "sudo rm -rf /"   # dry-run: why does this classify the way it does?
argus stats                     # decision digest
argus serve                     # local web UI: live tail, policy editor, replay
```

## Why it's worth having

- **A severity ladder, not a switch** — a scratch `rm` isn't treated like wiping `/`.
- **Parses the real shell AST, never regexed** — obfuscation is seen and
  escalated, not bypassed.
- **A non-bypassable `high` floor** — disk wipes, `curl … | sh`, `rm -rf /`, and
  credential-file writes are always denied, in every mode.
- **Research-backed ruleset** — traces to MITRE ATT&CK, OWASP, and real incident
  postmortems, not guesswork.
- **Fails closed. Local-first** — no network calls, no telemetry.

## Learn more

Full docs, the policy-authoring guide, and the research behind the built-in
rules: <https://github.com/lucasngucii/Argus>. MIT licensed.
