package policy

// leadBoundary anchors a self-protect/credential Raw pattern's start so it
// fires on a real path segment — start of subject, after a path separator,
// or after a shell word boundary (whitespace/`;`/`&`/`|`/`(`/quote) — never
// mid-word. Without it, `(^|/)` alone misses a bare relative path like the
// "bin/argus" in `rm bin/argus`, which is preceded by a space, not `/`.
const leadBoundary = `(^|[\s;&|("'/])`

// trailBoundary closes the segment: either it continues deeper (`/`), or the
// shell word ends right there — whitespace, `;`, `&`, `|`, `)`, quote, or
// end-of-subject. Deliberately not `\b`: `\b` would also accept `-` and `.`,
// letting `bin/argus-cli` (an unrelated binary) or `bin/argus.bak` false-
// positive. Without this at all, `rm bin/argus&&echo` escapes: `\s|$` alone
// doesn't cover the metacharacter sitting directly against the path.
const trailBoundary = `(/|[\s;&|)"']|$)`

// Default returns the effective policy with no overrides (baseline only) —
// the fail-closed fallback for a missing/unreadable policy.json (gate, web
// explain).
func Default() Policy {
	return File{Version: 1}.Effective()
}

// Baseline returns the binary-owned seed rules — the medium-severity "ask"
// coverage every install gets, reassembled from the binary on every load so
// a newer binary's rules reach existing installs without a re-init. Like
// Floor(), it is never stored in policy.json; the file carries only
// per-baseline overrides (see File) and user rules.
func Baseline() []Rule {
	return []Rule{
		{ID: "rm-recursive", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "rm -r directory",
			Match:             Match{Cmd: []string{"rm"}, Flags: []string{"r"}, TargetScorer: "rm_target"},
			ContextEscalation: []Escalation{{When: Condition{CWDMatches: "prod"}, To: "high"}}},
		{ID: "git-danger", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "git force/hard-reset/clean",
			Match: Match{Cmd: []string{"git"}, TargetScorer: "git_danger"}}, // precise: only --force/reset --hard/clean -f
		{ID: "sudo", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "sudo",
			Match: Match{Cmd: []string{"sudo"}}},
		{ID: "docker-service", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "docker service/prod op",
			// Both the `docker` subcommand form and the legacy hyphenated
			// `docker-compose` binary — the latter is its own command name, so it
			// must be listed explicitly (matchedCommands' family-prefix is "." only).
			Match: Match{Cmd: []string{"docker", "docker-compose"}, ArgsContain: []string{"service", "stack", "swarm", "prune", "down"}}},
		{ID: "db-write", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "DB client write",
			Match: Match{Cmd: []string{"psql", "mongosh", "mongo", "clickhouse-client"},
				ArgMatches: `(?i)\b(insert\s+into|update\s|create\s+(table|database)|alter\s|grant\s)\b`}},
		{ID: "opaque-exec", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "opaque script/subshell — cannot inspect",
			// Raw (full command), not ArgMatches (joined args): the interpreter
			// name (`bash`, `sh`) is the command word, never an arg, so the
			// `(bash|sh|zsh)\s+…\.sh` alternative could never fire against args
			// alone. The lead `[^-|;&]` guard keeps `bash --version` benign.
			Match: Match{Raw: `(?i)\b(bash|sh|zsh)\s+[^-|;&]+\.sh\b|-c\s`}},
		{ID: "grep-exfil", Enabled: true, Severity: "medium", Tool: []string{"Bash"},
			// Credential search piped to a network sink — the documented grep→curl
			// exfiltration shape (arXiv:2509.22040). medium (ask): a keyword heuristic,
			// so it must stay downgradable, not a non-recoverable floor.
			Match:  Match{Raw: `(?i)\b(grep|rg|ag)\b[^|]*(key|token|secret|credential|password)[^|]*\|\s*(curl|wget|nc|ncat)\b`},
			Reason: "credential search piped to network exfiltration"},
		{ID: "useradd-privileged", Enabled: true, Severity: "medium", Tool: []string{"Bash"},
			// Creating/elevating a privileged account (sudo/wheel group) is a documented
			// persistence step (arXiv:2509.22040). Exact-token argsContain (not a regex on
			// "admin") so a user NAMED admin doesn't false-positive.
			Match:  Match{Cmd: []string{"useradd", "usermod", "adduser"}, ArgsContain: []string{"sudo", "wheel"}},
			Reason: "privileged account creation/elevation (persistence)"},
		{ID: "pkg-install-lifecycle", Enabled: true, Severity: "medium", Tool: []string{"Bash"},
			// npm install/i/ci/update runs code via lifecycle hooks (supply-chain RCE
			// vector; Microsoft Mastra, Trend Micro Axios). Anchored so `npm i` matches
			// and `npm run ci` does not. RE2 has no lookahead, so `--ignore-scripts`
			// (the safe form) still asks — allowlist it if you want it silent.
			Match:  Match{Cmd: []string{"npm"}, ArgMatches: `^(install|i|ci|update)\b`},
			Reason: "npm install runs code via lifecycle hooks (supply-chain); --ignore-scripts still asks"},
		{ID: "rc-file-inject", Enabled: true, Severity: "medium", Tool: []string{"Bash"},
			// A shell redirect into ~/.bashrc/~/.zshrc is a documented persistence
			// technique (arXiv:2509.22040). Matches the redirect shape only, so reading a
			// dotfile does not fire. medium/ask — editing dotfiles can be legitimate.
			Match:  Match{Raw: `>>?\s*\S*\.(bash|zsh)rc\b`},
			Reason: "shell redirect into a shell rc file (persistence)"},
		{ID: "mcp-mutating-tool", Enabled: true, Severity: "medium", Tool: []string{"mcp"},
			// No shell AST for MCP — the tool name is the only intent signal. Snake_case
			// is the norm, so verbs are anchored on _ / start / end (\b does NOT split _).
			Match:  Match{McpTool: `(?i)(^|_)(delete|drop|remove|destroy|truncate|write|create|update|put|patch|exec|run|kill|send|publish|revoke|deploy|merge|apply|grant|transfer)(_|$)`},
			Reason: "MCP tool with a mutating action — review before running"},
		{ID: "mcp-destructive-sql-args", Enabled: true, Severity: "medium", Tool: []string{"mcp"},
			// Destructive SQL in MCP arguments. medium (ask), not a floor: args are
			// freeform JSON, so this keyword heuristic must stay downgradable — consistent
			// with the Bash db-write rule's severity for the same class of signal.
			Match:  Match{Raw: `(?i)\b(drop|truncate)\s+(table|database)\b|\bdelete\s+from\b|\.drop\(\)|deletemany`},
			Reason: "destructive SQL in MCP tool arguments"},
		{ID: "mcp-read-sensitive-path", Enabled: true, Severity: "medium", Tool: []string{"mcp"},
			// The read-side counterpart to the mcp-fileop-sensitive-path floor: a
			// READ-verb MCP tool whose args target a credential/self-protect path.
			// Bash floors credential *reads* (credential-system-write matches the path
			// for any verb, cat included) but the MCP floor is AND-gated on a MUTATING
			// verb, so reading a key over MCP would otherwise slip through — a real
			// exfil path for a prompt-injected agent. medium (ask), not a floor: like
			// the SQL-args rule, the path lives in freeform JSON, so it stays
			// downgradable. AND-gated on BOTH the read verb AND the path, mirroring the
			// floor, so a non-read tool merely mentioning such a path is not escalated.
			// The path arm is copied from mcp-fileop-sensitive-path (inlined, not
			// extracted — the two are the mutating/read halves of one surface).
			Match: Match{
				McpTool: `(?i)(^|_)(read|get|fetch|load|open|download|cat|show|view|dump|export|tail|head|print)(_|$)`,
				Raw: leadBoundary + `\.ssh/(id_[A-Za-z0-9_]+|authorized_keys)\b` +
					`|` + leadBoundary + `\.ssh` + trailBoundary +
					`|` + leadBoundary + `\.aws/credentials\b` +
					`|` + leadBoundary + `\.aws` + trailBoundary +
					`|` + leadBoundary + `\.argus` + trailBoundary +
					`|` + leadBoundary + `\.claude/settings(\.local)?\.json\b` +
					`|` + leadBoundary + `\.claude` + trailBoundary +
					`|/etc/sudoers\b`},
			Reason: "MCP read-op targeting a credential/system/self-protect path"},
	}
}

// Floor returns the built-in always-high rules no policy or allowlist can
// downgrade (CLAUDE.md §4), plus Argus's self-protection rules. It is
// home-independent: callers never need a policy file to get the floor.
func Floor() []Rule {
	f := []Rule{
		// Recursive rm of a catastrophic target (root, home, a system dir,
		// `..` traversal, or a target the AST couldn't resolve). This lives in
		// the floor — not just Default()'s rm-recursive — so the catch survives
		// an empty or hand-edited user policy (spec §1.1/§1.4: the floor is an
		// engine invariant, not contingent on a well-formed policy file).
		// Deliberately NOT AlwaysHigh and base Severity "low": that keeps an
		// ordinary `rm -r <path>` at its scorer verdict (low/medium, still
		// downgradable). Only a scorer-"high" target pins the floor, via
		// classify.Classify. Flags{"r"} mirrors rm-recursive, so this rule
		// changes no severity Default() didn't already produce (max wins).
		{ID: "rm-catastrophic", Enabled: true, Severity: "low", Tool: []string{"Bash"},
			Match:  Match{Cmd: []string{"rm"}, Flags: []string{"r"}, TargetScorer: "rm_target"},
			Reason: "recursive rm of a catastrophic target"},
		{ID: "disk-format", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			// dd/diskutil are dangerous by their device argument: reading or writing
			// a raw device (if=…, of=/dev/…) or an erase. of=/dev/ closes the
			// write-only overwrite (`dd of=/dev/sda`, no if=). mkfs is handled by the
			// disk-mkfs rule below — it is destructive by invocation, with no such
			// arg to gate on, so it cannot share this ArgMatches gate.
			Match: Match{Cmd: []string{"dd", "fdisk", "diskutil"}, ArgMatches: `if=|of=/dev/|erase`}, Reason: "disk/format"},
		{ID: "disk-mkfs", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			// Any mkfs-family command (mkfs, mkfs.ext4, mkfs.xfs, …) formats a
			// device — destructive by invocation, so no arg gate. matchedCommands
			// credits the mkfs.<fstype> variants against the bare "mkfs" name; the
			// exact-name gate on "mkfs" alone missed the common typed forms.
			Match: Match{Cmd: []string{"mkfs"}}, Reason: "mkfs format"},
		{ID: "forkbomb", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{Raw: `:\(\)\s*\{`}, Reason: "forkbomb"},
		{ID: "pipe-to-shell", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{PipesInto: []string{"sh", "bash", "zsh"}}, Reason: "pipe-to-shell"},
		{ID: "db-destructive", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{ArgMatches: `(?i)\b(drop|truncate)\s+(table|database)\b|\bdelete\s+from\b|\.drop\(\)|deletemany`}, Reason: "DB destructive"},
		{ID: "credential-system-write", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash", "Write", "Edit"},
			// Two forms per credential dir: a file inside it (…/id_rsa,
			// …/id_rsa.pub — the .pub case is over-inclusive but fail-safe, so
			// left as-is; …/credentials), and the bare directory itself as the
			// delete target (`rm -rf ~/.ssh`), which has neither a trailing
			// "/" nor (for a relative path) a leading "/" to anchor on.
			Match: Match{Raw: leadBoundary + `\.ssh/(id_[A-Za-z0-9_]+|authorized_keys)\b` +
				`|` + leadBoundary + `\.ssh` + trailBoundary +
				`|` + leadBoundary + `\.aws/credentials\b` +
				`|` + leadBoundary + `\.aws` + trailBoundary +
				`|>\s*/etc/|/etc/sudoers\b`},
			Reason: "credential file or system-config write"},
		{ID: "mcp-fileop-sensitive-path", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"mcp"},
			// A FILE-OP-named MCP tool whose args target a credential/system/self-protect
			// path. AND-gated on BOTH signals so a non-file-op tool merely mentioning such
			// a path in freeform args (a docs search, a chat message) is NOT floored — the
			// floor stays reserved for a real write/delete against a sensitive target.
			Match: Match{
				McpTool: `(?i)(^|_)(write|delete|remove|move|copy|create|put|append|truncate|chmod|unlink)(_|$)`,
				Raw: leadBoundary + `\.ssh/(id_[A-Za-z0-9_]+|authorized_keys)\b` +
					`|` + leadBoundary + `\.ssh` + trailBoundary +
					`|` + leadBoundary + `\.aws/credentials\b` +
					`|` + leadBoundary + `\.aws` + trailBoundary +
					`|` + leadBoundary + `\.argus` + trailBoundary +
					`|` + leadBoundary + `\.claude/settings(\.local)?\.json\b` +
					`|` + leadBoundary + `\.claude` + trailBoundary +
					`|/etc/sudoers\b|>\s*/etc/`},
			Reason: "MCP file-op targeting a credential/system/self-protect path"},
	}
	return append(f, SelfProtectRules()...)
}

// SelfProtectRules returns the rules that keep an agent from disarming Argus
// itself (CLAUDE.md §5): the Claude Code hook wiring that invokes the gate,
// and Argus's own config/db/binary. Every match is a home-independent regex
// on Match.Raw (never os.UserHomeDir — see the doc comment on Floor callers
// in classify.Classify, which must stay pure); RedirectsTo is exact-string
// membership, not regex, so it cannot express these suffix patterns.
func SelfProtectRules() []Rule {
	return []Rule{
		// Both the settings file itself AND the bare .claude dir as a delete
		// target (`rm -rf ~/.claude` has no trailing "/" to anchor the first
		// alternative on).
		{ID: "self-protect-claude-settings", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash", "Write", "Edit"},
			Match: Match{Raw: leadBoundary + `\.claude/settings(\.local)?\.json\b` +
				`|` + leadBoundary + `\.claude` + trailBoundary},
			Reason: "self-protection: Claude Code hook wiring"},
		// Both the .argus dir (bare-directory delete included, same reasoning
		// as above) AND the binary — see leadBoundary/trailBoundary for why a
		// plain (^|/)…(\s|$) anchor missed both a relative `bin/argus` (no
		// leading "/") and a metachar-adjacent one (`rm bin/argus&&echo`).
		{ID: "self-protect-argus", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash", "Write", "Edit"},
			Match: Match{Raw: leadBoundary + `\.argus` + trailBoundary +
				`|` + leadBoundary + `bin/argus` + trailBoundary},
			Reason: "self-protection: argus config/db/binary"},
	}
}
