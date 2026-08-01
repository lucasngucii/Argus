package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// Init sets up ~/.argus (seed policy + SQLite store) and wires the named
// harness's PreToolUse hook that runs `argus gate`, without disturbing
// anything already in its config file (see Wire). It is safe to run more
// than once:
//   - policy.json is left alone if it already exists — Init seeds a
//     starting policy, it never overwrites one a user may have since edited.
//   - the version-1 policy_versions row is only inserted the first time
//     (version is the table's PRIMARY KEY, so re-stamping "seed" over an
//     edited policy would also just be a lie).
//   - the PreToolUse hook is only appended if no existing entry already
//     references `argus gate` (see wireHook).
//   - the legacy decisions.jsonl import runs at most once (see
//     importLegacyDecisions).
func Init(home, harness string) error {
	argusDir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argusDir, 0o700); err != nil {
		return fmt.Errorf("init: create %s: %w", argusDir, err)
	}

	policyJSON, err := seedPolicy(filepath.Join(argusDir, "policy.json"))
	if err != nil {
		return err
	}

	dbPath := filepath.Join(argusDir, "argus.db")
	if err := seedPolicyVersion(dbPath, policyJSON); err != nil {
		return err
	}

	if err := Wire(harness, home); err != nil {
		return err
	}

	importLegacyDecisions(home, dbPath)
	return nil
}

// seedPolicy writes the default policy to path unless a policy already
// exists there. It returns the JSON now on disk either way, since the
// caller needs those exact bytes to hash and stamp into policy_versions.
func seedPolicy(path string) ([]byte, error) {
	existing, err := os.ReadFile(path)
	if err == nil {
		return existing, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("init: read existing policy.json: %w", err)
	}

	b, err := json.MarshalIndent(policy.DefaultFile(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("init: marshal default policy: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("init: write policy.json: %w", err)
	}
	return b, nil
}

// seedPolicyVersion records the version-1 audit-trail snapshot the first
// time Init runs against dbPath; a repeat run sees an existing row and
// leaves it alone.
func seedPolicyVersion(dbPath string, policyJSON []byte) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("init: open store: %w", err)
	}

	n, err := st.PolicyVersionCount()
	if err != nil {
		return fmt.Errorf("init: count policy versions: %w", err)
	}
	if n > 0 {
		return nil
	}

	sum := sha256.Sum256(policyJSON)
	if err := st.InsertPolicyVersion(1, "init", "seed", string(policyJSON), hex.EncodeToString(sum[:])); err != nil {
		return fmt.Errorf("init: insert policy version: %w", err)
	}
	return nil
}
