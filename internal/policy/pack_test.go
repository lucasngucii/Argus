package policy

import (
	"os"
	"testing"
)

// The shipped infra pack must stay schema-valid so a copy-paste can't silently
// rot.
func TestInfraPackValidates(t *testing.T) {
	b, err := os.ReadFile("../../docs/policy-packs/infra.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(b); err != nil {
		t.Fatalf("shipped infra pack invalid: %v", err)
	}
}
