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

// Default returns the seed policy Argus ships with. It intentionally does
// not embed Floor(): the classifier applies the floor as a separate pass on
// every decision, so embedding it here would double-evaluate it.
func Default() Policy {
	p := Policy{Version: 1, Meta: map[string]string{"seed": "agent-review v2"}}
	p.Rules = []Rule{
		{ID: "rm-recursive", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "rm -r directory",
			Match:             Match{Cmd: []string{"rm"}, Flags: []string{"r"}, TargetScorer: "rm_target"},
			ContextEscalation: []Escalation{{When: Condition{CWDMatches: "prod"}, To: "high"}}},
		{ID: "git-danger", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "git force/hard-reset/clean",
			Match: Match{Cmd: []string{"git"}, TargetScorer: "git_danger"}}, // precise: only --force/reset --hard/clean -f
		{ID: "sudo", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "sudo",
			Match: Match{Cmd: []string{"sudo"}}},
		{ID: "docker-service", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "docker service/prod op",
			Match: Match{Cmd: []string{"docker"}, ArgsContain: []string{"service", "stack", "swarm", "prune", "down"}}},
		{ID: "db-write", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "DB client write",
			Match: Match{Cmd: []string{"psql", "mongosh", "mongo", "clickhouse-client"},
				ArgMatches: `(?i)\b(insert\s+into|update\s|create\s+(table|database)|alter\s|grant\s)\b`}},
		{ID: "opaque-exec", Enabled: true, Severity: "medium", Tool: []string{"Bash"}, Reason: "opaque script/subshell — cannot inspect",
			// Raw (full command), not ArgMatches (joined args): the interpreter
			// name (`bash`, `sh`) is the command word, never an arg, so the
			// `(bash|sh|zsh)\s+…\.sh` alternative could never fire against args
			// alone. The lead `[^-|;&]` guard keeps `bash --version` benign.
			Match: Match{Raw: `(?i)\b(bash|sh|zsh)\s+[^-|;&]+\.sh\b|-c\s`}},
	}
	return p
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
			Match: Match{Cmd: []string{"dd", "mkfs", "fdisk", "diskutil"}, ArgMatches: `if=|erase`}, Reason: "disk/format"},
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
