package classify

import (
	"testing"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
)

// TestCannotDisarm asserts an agent cannot lower its own leash: touching the
// Claude Code hook wiring or Argus's own policy/db, from any home directory,
// always classifies high — regardless of what the loaded policy says.
func TestCannotDisarm(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/Users/x/.claude/settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -f /home/y/.argus/policy.json"}},
		{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/root/.argus/argus.db"}},
		// The background-serve pid file lives under .argus/, so faking it dead
		// to spawn a rogue server must not be a low-severity write.
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/home/y/.argus/argus.pid"}},
	}
	for _, p := range cases {
		if Classify(p, pol).Severity != "high" {
			t.Fatalf("self-protection breach: %+v", p.ToolInput)
		}
	}
}

// TestCannotDisarmHomeIndependent re-runs the settings.json/policy.json/db
// cases under a second, unrelated home layout (relative path, Windows-style
// drive, container path) to confirm the rules key off path suffix, never an
// absolute home prefix.
func TestCannotDisarmHomeIndependent(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: ".claude/settings.local.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat /var/lib/svc/.argus/policy.json"}},
		{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/opt/agent/.argus/argus.db"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "chmod +x /srv/build/bin/argus"}},
	}
	for _, p := range cases {
		if Classify(p, pol).Severity != "high" {
			t.Fatalf("self-protection breach: %+v", p.ToolInput)
		}
	}
}

// TestCredentialAndSystemWriteAlwaysHigh closes the cross-task gap: the old
// agent-review gate treated credential files and system-config writes as
// high, and the Floor() rewrite lost that. An SSH private key write and a
// shell redirect into /etc/ must both classify high.
func TestCredentialAndSystemWriteAlwaysHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/home/y/.ssh/id_rsa"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/root/.ssh/id_ed25519"}},
		{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/home/y/.ssh/authorized_keys"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat /home/y/.aws/credentials"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "echo x > /etc/hosts"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "echo 'evil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/etc/sudoers"}},
	}
	for _, p := range cases {
		if Classify(p, pol).Severity != "high" {
			t.Fatalf("credential/system-write breach: %+v", p.ToolInput)
		}
	}
}

// TestCredentialSystemWriteCaseInsensitive pins the case-insensitivity fix
// (docs/superpowers/specs/2026-07-30-selfprotect-case-insensitivity-fix.md):
// ~/.ssh and ~/.SSH name the same directory on a case-insensitive filesystem,
// so an alternate-case credential path must still hit the credential-system-
// write floor.
func TestCredentialSystemWriteCaseInsensitive(t *testing.T) {
	pol := policy.Default()
	p := hook.Payload{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat ~/.SSH/id_rsa"}}
	if got := Classify(p, pol).Severity; got != "high" {
		t.Fatalf("case-insensitive credential-system-write bypass (got %s): %+v", got, p.ToolInput)
	}
}

// TestCredentialRulesStayFailSafe asserts the credential/system-write floor
// doesn't over-match benign paths that merely mention "aws"/"ssh"/"etc" —
// the fail-safe requirement is over-block real secrets, not any file that
// shares a substring with one.
func TestCredentialRulesStayFailSafe(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/repo/internal/aws/client.go"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "grep aws README.md"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat /etc/hosts"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/repo/docs/ssh-notes.md"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "app/settings.json"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "docs/aws-guide.md"}},
	}
	for _, p := range cases {
		if got := Classify(p, pol).Severity; got == "high" {
			t.Fatalf("false positive: %+v classified high", p.ToolInput)
		}
	}
}

// TestBareDirectoryDeleteIsHigh covers the review-flagged Critical 1: the
// original patterns anchored on a trailing "/" (…/.argus/…), so deleting the
// directory itself — which never has a trailing "/" or further path after
// it — matched nothing and fell through to the generic rm-recursive medium
// rule. `rm -rf ~/.argus` (etc.) must classify high exactly like deleting a
// file inside it.
func TestBareDirectoryDeleteIsHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.argus"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.ssh"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.aws"}},
		// Same gap, relative form: no "~" means no leading "/" either, which
		// (^|/) alone (the pre-fix anchor) also missed.
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf .argus"}},
	}
	for _, p := range cases {
		if got := Classify(p, pol).Severity; got != "high" {
			t.Fatalf("bare directory delete not caught (got %s): %+v", got, p.ToolInput)
		}
	}
}

// TestMetacharAdjacentBinaryDeleteIsHigh covers the review-flagged Critical
// 2: the original bin/argus pattern anchored its trailing boundary on
// whitespace-or-end, so ordinary shell chaining with no space before the
// metacharacter (`rm bin/argus&&echo done`) matched nothing and the whole
// command classified safe.
func TestMetacharAdjacentBinaryDeleteIsHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm bin/argus&&echo done"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -f bin/argus;echo x"}},
	}
	for _, p := range cases {
		if got := Classify(p, pol).Severity; got != "high" {
			t.Fatalf("metachar-adjacent binary delete escaped (got %s): %+v", got, p.ToolInput)
		}
	}
}

// TestClaudeSettingsAndBareDirAlwaysHigh is a "must stay high" regression
// guard pinning the verification table from
// docs/superpowers/specs/2026-07-30-self-protect-claude-scope-fix.md rows 1-6:
// the settings.json path (plain and `./`-obfuscated), the bare .claude dir,
// and its double-slash/dot-alias/parent-traversal variants must all classify
// high via self-protect-claude-settings. Most of these rows already passed
// against the old, broader pre-fix regex (which matched ANY subpath under
// .claude/, obfuscated or not) — this test does not prove a fix transition,
// it pins that narrowing the pattern to bareDirBoundary never lost these
// cases. See TestClaudeSettingsSeparatorNoiseBypass for the genuine
// obfuscation-transition regression (the `[./]*` fix in commit e620267's
// follow-up).
func TestClaudeSettingsAndBareDirAlwaysHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/Users/x/.claude/settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat ~/.claude/./././settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude//"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude/."}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cp -r ~/.claude/.. /tmp/x"}},
	}
	for _, p := range cases {
		d := Classify(p, pol)
		if d.Severity != "high" {
			t.Fatalf("self-protection breach (got %s): %+v", d.Severity, p.ToolInput)
		}
	}
}

// TestClaudeSettingsSeparatorNoiseBypass is the genuine obfuscation-transition
// regression guard: commit e620267 hardened the settings.json alternative
// with `(\./)*` tolerance for `./`-noise, but `(\./)*` only matches repeated
// "./" pairs, not a bare double-slash — so `.claude//settings.json` (which
// collapses to the same file as `.claude/settings.json` on any filesystem)
// bypassed the floor entirely. The same gap existed, worse, on the new
// `.claude/projects` alternative added in the same commit: it had ZERO
// separator tolerance, so even `.claude/./projects` (let alone `//`) bypassed
// the projects-exfil protection outright. These cases were CONFIRMED to fail
// against the `(\./)*`/no-tolerance Raw pattern and to pass after replacing
// both separator-tolerance spots with `[./]*` (matching bareDirBoundary's
// existing "any run of dot/slash" convention).
func TestClaudeSettingsSeparatorNoiseBypass(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat ~/.claude//settings.json"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cp -r ~/.claude/./projects /tmp/exfil"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cp -r ~/.claude//projects /tmp/exfil"}},
	}
	for _, p := range cases {
		d := Classify(p, pol)
		if d.Severity != "high" {
			t.Fatalf("separator-noise self-protect bypass (got %s): %+v", d.Severity, p.ToolInput)
		}
	}
}

// TestClaudeProjectsWholeDirAlwaysHigh pins verification table rows 7-8: the
// new nhánh 3. `.claude/projects` is now protected as its own whole-directory
// reference (spec design decision 4), same reasoning as bare `.claude`.
func TestClaudeProjectsWholeDirAlwaysHigh(t *testing.T) {
	pol := policy.Default()
	cases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude/projects"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cp -r ~/.claude/projects /tmp/exfil"}},
	}
	for _, p := range cases {
		d := Classify(p, pol)
		if d.Severity != "high" {
			t.Fatalf("self-protection breach (got %s): %+v", d.Severity, p.ToolInput)
		}
	}
}

// TestClaudeProjectsSubpathNotSelfProtected pins verification table rows 9-10
// — the reported bug and its fix. Narrowing the bare-dir alternative to a
// real whole-directory boundary (bareDirBoundary) means a genuinely distinct
// subpath under .claude/projects (an individual project's memory file, or one
// specific project's directory) is no longer floored by self-protect. This is
// the false positive the spec exists to close: before the fix, the old
// trailBoundary matched `.claude` followed directly by "/", with no further
// look-ahead, so ANY subpath — including these two — was caught and floored
// to high via self-protect-claude-settings.
// TestSelfProtectCaseInsensitiveClaude pins the case-insensitivity fix from
// docs/superpowers/specs/2026-07-30-selfprotect-case-insensitivity-fix.md:
// ~/.claude and ~/.argus name the SAME directory on a case-insensitive
// filesystem (macOS/Windows) regardless of casing, so an alternate-case
// bare-dir delete must still hit the floor, not just the canonical-case form.
func TestSelfProtectCaseInsensitiveClaude(t *testing.T) {
	pol := policy.Default()
	p := hook.Payload{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.CLAUDE"}}
	if got := Classify(p, pol).Severity; got != "high" {
		t.Fatalf("case-insensitive self-protect-claude-settings bypass (got %s): %+v", got, p.ToolInput)
	}
}

func TestSelfProtectCaseInsensitiveArgus(t *testing.T) {
	pol := policy.Default()
	p := hook.Payload{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.ARGUS"}}
	if got := Classify(p, pol).Severity; got != "high" {
		t.Fatalf("case-insensitive self-protect-argus bypass (got %s): %+v", got, p.ToolInput)
	}
}

// TestCannotSelfDisarmViaUninstall pins the net-new self-disarm vector: `argus
// uninstall` removes the gate's own hook (and --purge deletes the policy +
// history) by the SUBCOMMAND VERB, which the path-based self-protect rules can't
// see. A prompt-injected agent must not disarm the gate with one allowed
// command, so the resolved `argus uninstall` invocation floors high (→ deny).
// Disarming stays possible for a human at their own terminal, where the hook
// never fires. Variable indirection still resolves to the same command.
func TestCannotSelfDisarmViaUninstall(t *testing.T) {
	pol := policy.Default()
	for _, cmd := range []string{
		"argus uninstall",
		"argus uninstall --purge",
		"a=argus; $a uninstall",              // resolved via indirection
		"/usr/local/bin/argus uninstall",     // covered by the bin/argus rule
		"./argus uninstall",                  // path-qualified — basename match
		"dist/argus uninstall --purge",       // relative build path
		"/opt/argus/argus uninstall",         // path with no bin/ segment
		"cd /tmp && argus uninstall --purge", // in a chain
	} {
		p := hook.Payload{ToolName: "Bash", ToolInput: hook.ToolInput{Command: cmd}}
		if got := Classify(p, pol).Severity; got != "high" {
			t.Fatalf("%q must floor high (self-disarm), got %s", cmd, got)
		}
	}
}

// TestUninstallFloorStaysFailSafe: matching resolved facts (not Raw subject
// text) keeps the floor precise — other argus subcommands and incidental
// mentions of the word "uninstall" in another command's args are NOT floored.
func TestUninstallFloorStaysFailSafe(t *testing.T) {
	pol := policy.Default()
	for _, cmd := range []string{
		"argus init",
		"argus doctor",
		"argus stats",
		"echo see argus uninstall in the docs", // command is echo, not argus
		`git commit -m "add argus uninstall"`,  // command is git
	} {
		p := hook.Payload{ToolName: "Bash", ToolInput: hook.ToolInput{Command: cmd}}
		if got := Classify(p, pol).Severity; got == "high" {
			t.Fatalf("%q must not be floored high, got %s", cmd, got)
		}
	}
}

// TestResolvedPathFloorsBeatQuoteAndVarSplit pins the fix for the audit's
// critical bypass: the path floors match the RESOLVED argv, not just the raw
// subject text, so quotes and variables the shell normalizes away can no longer
// hide a protected segment. `cat ~/."ssh"/id_rsa` is byte-identical to
// `cat ~/.ssh/id_rsa` to the shell and must floor the same.
func TestResolvedPathFloorsBeatQuoteAndVarSplit(t *testing.T) {
	pol := policy.Default()
	for _, cmd := range []string{
		`cat ~/."ssh"/id_rsa`,           // quote-split, no variable
		`cat ~/.ss''h/id_rsa`,           // adjacent-quote split
		`s=ssh; cat ~/.$s/id_rsa`,       // variable-assembled
		`a=aws; cat ~/.$a/credentials`,  // variable-assembled credential
		`tee ~/."claude"/settings.json`, // quote-split hook wiring write
		`v=argus; echo x > ~/.$v/db`,    // variable-assembled argus write (redirect)
	} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; got != "high" {
			t.Fatalf("%q must floor high via resolved argv, got %s", cmd, got)
		}
	}
	// A backslash-escaped protected segment (`.s\sh` = `.ssh`) must also floor.
	for _, cmd := range []string{`cat ~/.s\sh/id_rsa`, `cat ~/.cla\ude/settings.json`} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; got != "high" {
			t.Fatalf("%q (backslash-escaped) must floor high, got %s", cmd, got)
		}
	}
	// The resolved view must NOT over-match a benign path that merely resolves.
	for _, cmd := range []string{`ls ~/.ssh_backup`, `cat ~/.claude/projects/x/memory/f.md`} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; got == "high" {
			t.Fatalf("false positive: %q resolved to high", cmd)
		}
	}
	// The resolved-argv view must not make a structural rule cross a statement
	// boundary: `bash; cat deploy.sh` is two benign statements, not opaque-exec.
	for _, cmd := range []string{`bash; cat deploy.sh`, `sh; echo build.sh`} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; rank(got) >= rank("medium") {
			t.Fatalf("opaque-exec false positive across `;`: %q -> %s", cmd, got)
		}
	}
	// A genuine opaque exec still asks.
	if got := Classify(bash("bash deploy.sh", "default", "/tmp"), pol).Severity; rank(got) < rank("medium") {
		t.Fatalf("real `bash deploy.sh` must still ask, got %s", got)
	}
}

// TestDbDestructiveAnchoredToClients pins the false-positive fix: the
// db-destructive floor now fires only when a destructive statement is passed to
// a real DB client, not on any command whose text mentions "drop table".
func TestDbDestructiveAnchoredToClients(t *testing.T) {
	pol := policy.Default()
	// Must NOT floor: the phrase in a commit message / echo.
	for _, cmd := range []string{
		"echo drop table users",
		`git commit -m "drop table users migration"`,
		`git commit -m "delete from cache on logout"`,
	} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; got == "high" {
			t.Fatalf("false positive: %q floored high", cmd)
		}
	}
	// Must still floor: a destructive statement to an actual client, including
	// one fed via a pipe (the SQL is not the client's own arg).
	for _, cmd := range []string{
		`psql -c "drop table users"`,
		`mysql -e "delete from sessions"`,
		`echo "drop table users" | psql`,
		`duckdb -c "delete from t"`,
	} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; got != "high" {
			t.Fatalf("%q must floor high, got %s", cmd, got)
		}
	}
}

// TestEtcShadowFlooredForEveryVerb pins the fix for the audit's critical /etc
// gap: /etc/shadow (password hashes) and /etc/sudoers must floor high for a
// CONTENT read and any write, not only a shell redirect.
func TestEtcShadowFlooredForEveryVerb(t *testing.T) {
	pol := policy.Default()
	for _, cmd := range []string{
		"cat /etc/shadow", "grep root /etc/shadow", "cp /etc/shadow /tmp/x",
		"tee /etc/shadow", "chmod 777 /etc/shadow", "cp evil /etc/gshadow",
	} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; got != "high" {
			t.Fatalf("%q must floor high, got %s", cmd, got)
		}
	}
	// A pure metadata listing stays exempt (names/sizes are not the secret).
	if got := Classify(bash("stat /etc/shadow", "default", "/tmp"), pol).Severity; got == "high" {
		t.Fatalf("stat /etc/shadow (metadata) should be exempt, got %s", got)
	}
}

// TestRmSystemCriticalExtendedCoverage pins the widened coverage: /usr/lib64 and
// bare top-level dirs, still without dev-path false positives.
func TestRmSystemCriticalExtendedCoverage(t *testing.T) {
	pol := policy.Default()
	for _, cmd := range []string{"rm /usr/lib64/x.so", "rm /boot", "rm /bin", "unlink /lib64"} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; rank(got) < rank("medium") {
			t.Fatalf("%q must ask, got %s", cmd, got)
		}
	}
	for _, cmd := range []string{"rm /usr/local/lib64/x", "rm ./boot", "rm mybin"} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; rank(got) >= rank("medium") {
			t.Fatalf("false positive: %q -> %s", cmd, got)
		}
	}
}

// TestLeadBoundaryEqualsCatchesFlagValuePaths pins the leadBoundary `=` fix: a
// protected path supplied as a --flag=path value is no longer hidden by the `=`.
func TestLeadBoundaryEqualsCatchesFlagValuePaths(t *testing.T) {
	pol := policy.Default()
	if got := Classify(bash("git config --file=.claude/settings.json k v", "default", "/tmp"), pol).Severity; got != "high" {
		t.Fatalf("--file=.claude/settings.json must floor high, got %s", got)
	}
}

// TestMCPReadVerbSynonymsCatchCredentialReads pins the M5 fix: read-verb
// synonyms beyond the original list still escalate an MCP credential read.
func TestMCPReadVerbSynonymsCatchCredentialReads(t *testing.T) {
	pol := policy.Default()
	args := `{"path":"/home/x/.ssh/id_rsa"}`
	for _, tool := range []string{
		"mcp__fs__retrieve_file", "mcp__fs__slurp", "mcp__fs__access",
		"mcp__fs__pull", "mcp__fs__file_contents",
	} {
		if got := Classify(mcp(tool, args), pol).Severity; rank(got) < rank("medium") {
			t.Fatalf("%s reading a credential path must be >= medium, got %s", tool, got)
		}
	}
}

// TestRmSystemCriticalAsksButNotFalsePositive pins the rm-system-critical rule:
// deleting an irreplaceable system file (no recursion needed, so rm-recursive
// misses it) asks, while ordinary dev/ops paths that merely contain bin/lib/etc
// segments stay clear.
func TestRmSystemCriticalAsksButNotFalsePositive(t *testing.T) {
	pol := policy.Default()
	for _, cmd := range []string{
		"rm /boot/vmlinuz", "rm /bin/sh", "unlink /sbin/init",
		"rm /usr/bin/python3", "shred /etc/fstab",
	} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; rank(got) < rank("medium") {
			t.Fatalf("%q must ask (>= medium), got %s", cmd, got)
		}
	}
	for _, cmd := range []string{
		"rm ./bin/tool", "rm build/lib/x.so", "rm /usr/local/bin/mytool",
		"rm /etc/nginx/nginx.conf", "rm /home/u/bin/x", "rm dist/argus-cli",
	} {
		if got := Classify(bash(cmd, "default", "/tmp"), pol).Severity; rank(got) >= rank("medium") {
			t.Fatalf("false positive: %q classified %s", cmd, got)
		}
	}
}

// TestPathQualifiedScorerCommandsStillScore pins that a path-qualified command
// reaches its TargetScorer: basename matching made the rule fire, but the
// scorers compared the full name, so `/bin/rm -rf /` scored low (allow). The
// scorers now compare the basename too.
func TestPathQualifiedScorerCommandsStillScore(t *testing.T) {
	pol := policy.Default()
	if got := Classify(bash("/bin/rm -rf /", "default", "/tmp"), pol).Severity; got != "high" {
		t.Fatalf("/bin/rm -rf / must score high, got %s", got)
	}
	if got := Classify(bash("/usr/bin/rm -rf ~", "default", "/tmp"), pol).Severity; got != "high" {
		t.Fatalf("/usr/bin/rm -rf ~ must score high, got %s", got)
	}
	if got := Classify(bash("/usr/bin/git push --force", "default", "/tmp"), pol).Severity; rank(got) < rank("medium") {
		t.Fatalf("/usr/bin/git push --force must ask, got %s", got)
	}
}

func TestListingExemptionAllowsMetadataReads(t *testing.T) {
	for _, cmd := range []string{
		"ls ~/.argus", "ls ~/.claude", "ls ~/.ssh", "stat ~/.aws",
		"stat ~/.claude/settings.json", "du ~/.claude/projects",
		"ls ~/.argus && stat ~/.claude",
	} {
		if got := sev(cmd, "/tmp"); got != "safe" {
			t.Fatalf("%q: metadata listing must be safe, got %s", cmd, got)
		}
	}
}

func TestListingExemptionStillFloorsEverythingElse(t *testing.T) {
	for _, cmd := range []string{
		// writes/deletes
		"rm -rf ~/.claude", "rm -rf ~/.argus",
		"echo x > ~/.claude/settings.json", "cat a > ~/.argus/db",
		// content reads (the main line held)
		"cat ~/.claude/settings.json", "cat ~/.claude/settings.local.json",
		"grep token ~/.claude/settings.local.json",
		"cat ~/.ssh/id_rsa", "grep key ~/.aws/credentials",
		"cat ~/.argus/policy.json",
		// disguised writes/exec via non-listing verbs
		"find ~/.claude -delete", "sort -o ~/.claude/settings.json in",
		"uniq in ~/.argus/db",
		// git (all forms floored)
		"git -C ~/.claude show HEAD:settings.local.json",
		// structural
		"cat ~/.claude/x && rm -rf ~/.argus", "X=$(rm -rf ~/.claude)",
		"ls $(evil) ~/.claude", "ls ~/.claude | tee /other",
		`bash -c "ls ~/.claude"`,
	} {
		if got := sev(cmd, "/tmp"); rank(got) < rank("high") {
			t.Fatalf("%q must stay high, got %s", cmd, got)
		}
	}
}

func TestListingExemptionIsBashOnly(t *testing.T) {
	// A Write-tool payload to a protected path must stay floored (tool != Bash).
	for _, fp := range []string{"~/.claude/settings.json", "~/.ssh/id_rsa"} {
		p := hook.Payload{ToolName: "Write", PermissionMode: "default",
			ToolInput: hook.ToolInput{FilePath: fp}}
		if got := Classify(p, policy.Default()).Severity; rank(got) < rank("high") {
			t.Fatalf("Write to %q must stay high, got %s", fp, got)
		}
	}
}

func TestListingExemptionIsBuiltinFloorOnly(t *testing.T) {
	// A USER policy rule reusing a built-in floor ID must NOT get the exemption.
	pol := policy.File{Version: 1, Rules: []policy.Rule{{
		ID: "self-protect-argus", Enabled: true, AlwaysHigh: true, Severity: "high",
		Tool: []string{"Bash"}, Reason: "user rule", Match: policy.Match{Raw: `secretfile`},
	}}}.Effective()
	got := Classify(bash("ls secretfile", "default", "/tmp"), pol).Severity
	if rank(got) < rank("high") {
		t.Fatalf("user rule with built-in ID must still floor, got %s", got)
	}
}

func TestClaudeProjectsSubpathNotSelfProtected(t *testing.T) {
	pol := policy.Default()

	// A read of an individual project's own memory file must not be floored
	// by self-protect at all — it's an everyday, legitimate operation.
	readCases := []hook.Payload{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "cat ~/.claude/projects/x/memory/foo.md"}},
		{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/Users/x/.claude/projects/x/memory/foo.md"}},
	}
	for _, p := range readCases {
		d := Classify(p, pol)
		if d.RuleID == "self-protect-claude-settings" {
			t.Fatalf("false positive: self-protect-claude-settings fired on a legitimate project-memory path: %+v (severity %s)", p.ToolInput, d.Severity)
		}
	}

	// Deleting ONE specific project's directory is a genuinely distinct
	// subpath, not a dot-alias of .claude/projects itself — self-protect must
	// not floor it. It may still be scored (medium) by the general
	// rm-recursive rule independently; assert what it actually scores rather
	// than assuming.
	rmCase := hook.Payload{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "rm -rf ~/.claude/projects/x"}}
	d := Classify(rmCase, pol)
	if d.RuleID == "self-protect-claude-settings" {
		t.Fatalf("false positive: self-protect-claude-settings fired on a single project's subdirectory: %+v (severity %s)", rmCase.ToolInput, d.Severity)
	}
	if d.Severity != "medium" {
		t.Fatalf("rm -rf of a single project subdir: got severity %q, want %q (via rm-recursive)", d.Severity, "medium")
	}
}
