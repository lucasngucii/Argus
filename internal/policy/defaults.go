package policy

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
			Match: Match{ArgMatches: `(?i)\b(bash|sh|zsh)\s+[^-|;&]+\.sh\b|-c\s`}},
	}
	return p
}

// Floor returns the built-in always-high rules no policy or allowlist can
// downgrade (CLAUDE.md §4), plus Argus's self-protection rules. It is
// home-independent: callers never need a policy file to get the floor.
func Floor() []Rule {
	f := []Rule{
		{ID: "disk-format", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{Cmd: []string{"dd", "mkfs", "fdisk", "diskutil"}, ArgMatches: `if=|erase`}, Reason: "disk/format"},
		{ID: "forkbomb", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{Raw: `:\(\)\s*\{`}, Reason: "forkbomb"},
		{ID: "pipe-to-shell", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{PipesInto: []string{"sh", "bash", "zsh"}}, Reason: "pipe-to-shell"},
		{ID: "db-destructive", Enabled: true, AlwaysHigh: true, Severity: "high", Tool: []string{"Bash"},
			Match: Match{ArgMatches: `(?i)\b(drop|truncate)\s+(table|database)\b|\bdelete\s+from\b|\.drop\(\)|deletemany`}, Reason: "DB destructive"},
	}
	return append(f, SelfProtectRules()...)
}

// SelfProtectRules returns the rules that keep Argus from exempting its own
// config/binary/hook/db paths (CLAUDE.md §5).
//
// TODO(Task 8): real self-protection rules.
func SelfProtectRules() []Rule { return nil }
