package classify

import (
	"strings"

	"github.com/lucasngucii/argus/internal/hook"
	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/shellast"
)

// Decision is the classifier's verdict for one tool invocation: the chosen
// Severity, the RuleID and Reason that produced it, and whether the command
// carried an obfuscation/parse signal.
type Decision struct {
	Severity   string
	RuleID     string
	Reason     string
	Obfuscated bool
}

// order ranks severities so the classifier can take a max and compare against
// thresholds. It is the single source of truth for severity ordering.
var order = map[string]int{"safe": 0, "low": 1, "medium": 2, "high": 3}

// rank returns the numeric order of a severity. An unknown string ranks as
// high (fail-closed, CLAUDE.md §2): a typo or corrupt severity must never be
// treated as safer than it is.
func rank(s string) int {
	if v, ok := order[s]; ok {
		return v
	}
	return order["high"]
}

// hasDangerToken reports whether a destructive verb or pattern is visible in a
// piece of command text, even through shell-splitting evasion. It neutralizes
// shell punctuation ($IFS, backslashes, glued flags) to spaces before matching
// whole-word verbs, so `rm$IFS-rf$IFS/` still shows its `rm`. Punctuation-
// bearing patterns (a forkbomb, a redirect to root) are checked on the raw
// text, before neutralization erases them.
func hasDangerToken(s string) bool {
	s = strings.ToLower(s)
	for _, p := range []string{":()", "> /", ">/"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	// Collapse every non-alphanumeric rune to a space so a bare verb split by
	// $IFS or wrapped in punctuation surfaces as its own token.
	norm := " " + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return ' '
	}, s) + " "
	for _, v := range []string{
		"rm", "dd", "mkfs", "fdisk", "chmod", "chown",
		"shutdown", "reboot", "drop", "delete", "truncate",
	} {
		if strings.Contains(norm, " "+v+" ") {
			return true
		}
	}
	return false
}

// Classify decides the severity of a tool invocation against a policy. It is
// pure: no I/O, no clock, no globals mutated, and it never panics (CLAUDE.md
// §1). Severity is the max over matched non-Allow rules; an AlwaysHigh match
// pins high and marks a floor hit that nothing downstream can downgrade
// (§4). Obfuscation/parse failure and broken policy regexes escalate a
// visibly dangerous command rather than letting it slip through (§2).
func Classify(p hook.Payload, pol policy.Policy) Decision {
	f := shellast.Extract(p.Subject())
	best := Decision{Severity: "safe", Reason: "safe"}
	floorHit := false
	regexBroke := false

	consider := func(rules []policy.Rule) {
		for _, r := range rules {
			if !r.Enabled || r.Allow {
				continue
			}
			ok, rerr := Matches(p.ToolName, p.Subject(), f, r)
			if rerr {
				regexBroke = true
			}
			if !ok {
				continue
			}
			s := r.Severity
			if r.Match.TargetScorer != "" {
				if sc, has := Scorers[r.Match.TargetScorer]; has {
					s = sc(f)
					// A scorer verdict of "high" marks a catastrophic target
					// (root, home, a system dir, `..` traversal, or one the AST
					// couldn't resolve). That is an engine-level floor no
					// allowlist may downgrade — exactly like AlwaysHigh (CLAUDE.md
					// §4) — so pin floorHit. A medium/low target does NOT, so an
					// ordinary `rm -r <path>` stays downgradable.
					if s == "high" {
						floorHit = true
					}
				}
			}
			s = applyContext(s, r, p.CWD)
			// Key off the rule's own AlwaysHigh flag, not slice identity, so a
			// user policy's alwaysHigh rule is just as non-downgradable as the
			// built-in floor.
			if r.AlwaysHigh {
				s = "high"
				floorHit = true
			}
			if rank(s) > rank(best.Severity) {
				best = Decision{Severity: s, RuleID: r.ID, Reason: r.Reason, Obfuscated: f.Obfuscated}
			}
		}
	}
	consider(policy.Floor()) // built-in floor (owns its pass; Default() does not embed it)
	consider(pol.Rules)      // user/default rules (may carry AlwaysHigh too)

	// Obfuscation / parse-failure escalation, scoped to visible danger.
	if f.Obfuscated || !f.ParseOK {
		visibleDanger := hasDangerToken(p.Subject())
		for _, tok := range f.RawTokens {
			if hasDangerToken(tok + " ") {
				visibleDanger = true
			}
		}
		bump := "medium"
		if visibleDanger || floorHit || rank(best.Severity) >= rank("medium") {
			bump = "high"
		}
		if rank(bump) > rank(best.Severity) {
			best.Severity, best.Obfuscated = bump, true
			if best.Reason == "safe" {
				best.Reason = "obfuscated/unparseable"
			}
		}
	}

	// A broken policy regex must not silently drop a rule → escalate a
	// visible-danger command.
	if regexBroke && hasDangerToken(p.Subject()) && rank(best.Severity) < rank("medium") {
		best = Decision{Severity: "medium", Reason: "policy regex error (fail-closed)"}
	}

	// Allowlist downgrade — never below a floor hit.
	if !floorHit {
		best = applyAllowlist(best, p, f, pol)
	}
	return best
}

// applyContext raises a rule's severity when a ContextEscalation condition
// holds (currently: the working directory matches a named segment).
func applyContext(s string, r policy.Rule, cwd string) string {
	for _, e := range r.ContextEscalation {
		if e.When.CWDMatches != "" && pathHasSegment(cwd, e.When.CWDMatches) && rank(e.To) > rank(s) {
			s = e.To
		}
	}
	return s
}

// pathHasSegment reports whether needle names a whole path segment of path, or
// forms a hyphenated part of one (`prod` matches `/srv/prod-app` and
// `/x/app-prod`) — but not a mere substring, so `/x/reproduce/` never matches
// `prod`.
func pathHasSegment(path, needle string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == needle || strings.HasPrefix(seg, needle+"-") || strings.HasSuffix(seg, "-"+needle) {
			return true
		}
	}
	return false
}

// applyAllowlist lowers a decision to safe when an enabled Allow rule matches.
// The caller only invokes it when no floor was hit, so an AlwaysHigh verdict
// can never be downgraded here.
func applyAllowlist(best Decision, p hook.Payload, f shellast.Facts, pol policy.Policy) Decision {
	for _, r := range pol.Rules {
		if !r.Enabled || !r.Allow {
			continue
		}
		if ok, _ := Matches(p.ToolName, p.Subject(), f, r); ok {
			return Decision{Severity: "safe", RuleID: r.ID, Reason: "allowlisted: " + r.Reason}
		}
	}
	return best
}
