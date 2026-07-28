// Package policy defines the rule types Argus classifies commands against,
// and loads/validates policy documents from JSON.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// Match holds the conditions a Rule tests a command against. All non-empty
// fields must match for the rule to fire (see the classifier for the exact
// combination logic); Match itself carries no behavior.
type Match struct {
	Cmd          []string `json:"cmd,omitempty"`
	Flags        []string `json:"flags,omitempty"`
	ArgMatches   string   `json:"argMatches,omitempty"`  // regexp on joined args
	ArgsContain  []string `json:"argsContain,omitempty"` // ANY-of, against resolved args
	PipesInto    []string `json:"pipesInto,omitempty"`
	RedirectsTo  string   `json:"redirectsTo,omitempty"`
	TargetScorer string   `json:"targetScorer,omitempty"`
	Raw          string   `json:"raw,omitempty"` // regexp on subject (escape hatch)
}

// Condition is a predicate a ContextEscalation checks before raising a
// rule's severity.
type Condition struct {
	CWDMatches string `json:"cwdMatches,omitempty"`
}

// Escalation raises a rule's severity to To when When holds.
type Escalation struct {
	When Condition `json:"when"`
	To   string    `json:"to"`
}

// Rule is one policy entry: a match condition plus the verdict metadata the
// classifier attaches when it fires.
type Rule struct {
	ID                string       `json:"id"`
	Enabled           bool         `json:"enabled"`
	AlwaysHigh        bool         `json:"alwaysHigh,omitempty"`
	Allow             bool         `json:"allow,omitempty"` // allowlist/downgrade entry (Task 7)
	Tool              []string     `json:"tool"`
	Match             Match        `json:"match"`
	Severity          string       `json:"severity,omitempty"` // safe|low|medium|high (schema-enumerated)
	Reason            string       `json:"reason"`
	ContextEscalation []Escalation `json:"contextEscalation,omitempty"`
}

// Defaults holds document-wide toggles. OnError was removed: escalation on
// error is an invariant (CLAUDE.md §2), not a configurable knob.
type Defaults struct {
	Shadow bool `json:"shadow,omitempty"`
}

// Policy is a full policy document: version, metadata, defaults, and rules.
type Policy struct {
	Version  int               `json:"version"`
	Meta     map[string]string `json:"meta,omitempty"`
	Defaults Defaults          `json:"defaults,omitempty"`
	Rules    []Rule            `json:"rules"`
}

// Load reads and schema-validates the policy document at path. Validating
// before unmarshalling ensures malformed documents (bad severity,
// non-integer version, ...) are rejected with a precise schema error rather
// than silently coerced by Go's JSON decoder.
func Load(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("load policy: %w", err)
	}
	if err := Validate(b); err != nil {
		return Policy{}, fmt.Errorf("load policy %s: %w", path, err)
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return Policy{}, fmt.Errorf("load policy %s: decode policy: %w", path, err)
	}
	return p, nil
}
