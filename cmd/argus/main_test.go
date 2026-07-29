package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/lucasngucii/argus/internal/store"
)

// TestReplayCandidateThinSnapshotAssemblesBaseline proves the `replay
// --version` path assembles a stored thin snapshot through
// policy.EffectiveFromBytes — so it re-scores against the current binary
// baseline plus the snapshot's overrides, not an empty Policy.
func TestReplayCandidateThinSnapshotAssemblesBaseline(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	thin := `{"version":7,"overrides":{"sudo":{"enabled":false}},"rules":[]}`
	sum := sha256.Sum256([]byte(thin))
	if err := st.InsertPolicyVersion(7, "test", "thin", thin, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	cand, err := replayCandidate(st, dir, "", 7)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range cand.Rules {
		got[r.ID] = true
	}
	if !got["git-danger"] {
		t.Error("thin snapshot must re-score with the current binary baseline (git-danger)")
	}
	if got["sudo"] {
		t.Error("the snapshot's enabled:false override for sudo must be honored")
	}
}
