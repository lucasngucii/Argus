package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema.json
var schemaJSON []byte

// Validate schema-validates raw policy JSON bytes against schema.json,
// without unmarshalling into a Policy. It is the shared first pass behind
// both Load (file on disk) and any caller validating policy bytes received
// another way (e.g. an HTTP upload) — one schema-check path, one error
// shape, everywhere a policy document enters the system.
func Validate(b []byte) error {
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parse policy json: %w", err)
	}

	sch, err := compiledSchema()
	if err != nil {
		return fmt.Errorf("compile policy schema: %w", err)
	}
	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("validate policy: %w", err)
	}
	return nil
}

// compiledSchema compiles the embedded schema.json on each call. Policy
// validation happens a handful of times per process lifetime (startup,
// reload, admin upload), so recompiling is simpler than caching and not
// worth the shared state.
func compiledSchema() (*jsonschema.Schema, error) {
	var schemaDoc any
	if err := json.NewDecoder(bytes.NewReader(schemaJSON)).Decode(&schemaDoc); err != nil {
		return nil, fmt.Errorf("parse schema.json: %w", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", schemaDoc); err != nil {
		return nil, fmt.Errorf("add schema resource: %w", err)
	}
	return c.Compile("schema.json")
}

// SeedRuleIDs returns the IDs of Baseline()'s rules — the baseline rule set a
// fresh install seeds from. Derived from Baseline() rather than hard-coded so
// this list can never drift from the actual seed policy.
func SeedRuleIDs() []string {
	base := Baseline()
	ids := make([]string, 0, len(base))
	for _, r := range base {
		ids = append(ids, r.ID)
	}
	return ids
}
