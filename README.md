# Argus

**A permission gate for AI coding agents.** Argus classifies every shell command
and file write Claude Code tries to run as `safe / low / medium / high` and
decides **allow / ask / deny** — logging each decision so you can inspect and
tune it.

Local-first · pure-Go single binary · MIT.

## Install

```bash
npm install -g @agrus/argus
argus init      # sets up ~/.argus/ and wires the Claude Code hook (idempotent)
argus doctor    # check it's healthy
```

Claude Code now routes Bash/Write/Edit calls through Argus. Prebuilt for macOS &
Linux (arm64/x64); elsewhere: `go install github.com/lucasngucii/argus/cmd/argus@latest`.

## How it works

Argus installs as a Claude Code **PreToolUse hook**. Before a tool runs, Claude
pipes it to `argus gate`, which parses the command with a real shell parser,
classifies it, and returns a verdict:

| severity | verdict |
|---|---|
| safe, low | allow |
| medium | ask *(deny if the mode can't prompt)* |
| high | **deny — always** |

`high` is a non-bypassable floor: disk wipes, fork bombs, `curl … | sh`,
destructive SQL, `rm -rf /`, and writes to credential/system paths are denied in
every mode and can't be downgraded. Argus also protects its own config and hook.

Obfuscation (`X=rm; $X -rf /`, `… | base64 -d | sh`) is parsed, seen, and
**escalated** — never matched blindly. On any error it **fails closed**.

## Commands

| Command | What it does |
|---|---|
| `argus init` | Set up `~/.argus/` and wire the hook. |
| `argus doctor` | Verify the install. |
| `argus explain <cmd>` | Dry-run one command: severity, rule, verdict, parsed facts. |
| `argus stats [--jsonl]` | Decision digest / JSONL export. |
| `argus serve` | Local web UI (loopback): live tail, stats, explain, policy editor, replay. |
| `argus replay` | Re-score your history against a candidate policy. |
| `argus test <corpus>` | Assert `{command → severity}` (CI-friendly). |

## Custom rules

Policy is a JSON file (`~/.argus/policy.json`), schema-validated. Add your own:

```json
{
  "id": "terraform-destroy",
  "enabled": true, "alwaysHigh": true,
  "tool": ["Bash"], "severity": "high", "reason": "terraform destroy",
  "match": { "cmd": ["terraform"], "argsContain": ["destroy"] }
}
```

`match` fields (all must hold): `cmd`, `flags`, `argsContain`, `argMatches`,
`pipesInto`, `redirectsTo`, `raw` (regex on the whole command). Use `allow: true`
to whitelist a command — but nothing can downgrade the `high` floor. Edits apply
immediately, or edit + validate in the web **Policy** tab.

Beyond the built-in rules (grounded in the research at
[`docs/research/`](docs/research/)), see [`docs/policy-packs/`](docs/policy-packs/)
for optional rule sets (e.g. an infra teardown guard) you can merge in.

## Web UI

`argus serve` opens a loopback-only app at `127.0.0.1:4600`: live decision tail,
severity stats, an explain box, a validate-before-save policy editor, and a
**replay** simulator (*"this policy change flips 4 past decisions"*). Bound to
localhost only, with anti-DNS-rebinding + CSRF protection.

## Trust model

Argus is a classification layer, **not a sandbox** — it raises the bar and
creates an audit trail, it doesn't replace Claude Code's permissions or your OS
sandbox. It sees only the inline command: an interactive `psql` session's later
`DROP`, or an opaque `bash script.sh`, escalate to `ask`.

## Development

```bash
go build ./... && go test ./...
```

Pure-Go deps only: `mvdan/sh`, `modernc.org/sqlite`, `jsonschema`. Design + plans
in [`docs/`](docs/).

## License

[MIT](LICENSE).
