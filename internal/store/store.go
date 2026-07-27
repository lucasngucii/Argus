// Package store persists Argus decisions and policy versions to a local
// SQLite database. Writes are best-effort at the caller: the verdict is
// computed before, and independently of, any write here.
package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Row is one recorded decision.
type Row struct {
	TS             string
	Session        string
	CWD            string
	Tool           string
	Command        string
	File           string
	Severity       string
	Verdict        string
	PermissionMode string
	RuleID         string
	Harness        string
	PolicyVersion  int
	Obfuscation    bool
}

// Store is a handle to the Argus SQLite database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY,
  ts TEXT, session TEXT, cwd TEXT,
  tool TEXT, command TEXT, file TEXT,
  severity TEXT, verdict TEXT, permission_mode TEXT,
  rule_id TEXT,
  policy_version INTEGER,
  harness TEXT,
  obfuscation INTEGER
);
CREATE TABLE IF NOT EXISTS policy_versions (
  version INTEGER PRIMARY KEY,
  ts TEXT, author TEXT, note TEXT,
  policy_json TEXT,
  hash TEXT
);
`

// Open opens (creating if needed) the database at path in WAL mode and
// ensures both tables exist. The DSN sets _txlock=immediate so every
// BeginTx acquires the write lock up front, avoiding the deferred-txn
// upgrade failure documented in sqlite.org's locking notes.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(3000)&_pragma=journal_mode(WAL)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Insert records one decision. Callers treat this as best-effort: a
// logging failure must never change the verdict already returned to the
// caller.
func (s *Store) Insert(r Row) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	_, err = tx.Exec(
		`INSERT INTO decisions (ts, session, cwd, tool, command, file, severity, verdict, permission_mode, rule_id, policy_version, harness, obfuscation)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.TS, r.Session, r.CWD, r.Tool, r.Command, r.File, r.Severity, r.Verdict, r.PermissionMode, r.RuleID, r.PolicyVersion, r.Harness, r.Obfuscation,
	)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("insert decision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit decision: %w", err)
	}
	return nil
}

// Recent returns the most recent decisions, newest first, up to limit.
func (s *Store) Recent(limit int) ([]Row, error) {
	rows, err := s.db.Query(
		`SELECT ts, session, cwd, tool, command, file, severity, verdict, permission_mode, rule_id, policy_version, harness, obfuscation
		 FROM decisions ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query recent: %w", err)
	}
	defer rows.Close()

	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.TS, &r.Session, &r.CWD, &r.Tool, &r.Command, &r.File, &r.Severity, &r.Verdict, &r.PermissionMode, &r.RuleID, &r.PolicyVersion, &r.Harness, &r.Obfuscation); err != nil {
			return nil, fmt.Errorf("scan recent: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recent: %w", err)
	}
	return out, nil
}

// Counts returns the full-history count of decisions per severity.
func (s *Store) Counts() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM decisions GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("query counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var severity string
		var n int
		if err := rows.Scan(&severity, &n); err != nil {
			return nil, fmt.Errorf("scan counts: %w", err)
		}
		counts[severity] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate counts: %w", err)
	}
	return counts, nil
}

// PolicyVersionCount reports how many policy snapshots have been recorded.
// Doctor uses it to confirm `argus init` seeded the audit trail; Init uses
// it to avoid re-inserting the seed row on a repeat run (version is the
// table's PRIMARY KEY, so a duplicate insert would error).
func (s *Store) PolicyVersionCount() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM policy_versions`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count policy versions: %w", err)
	}
	return n, nil
}

// InsertPolicyVersion records a policy snapshot so replay and audit can
// reconstruct the exact policy in force at a given time.
func (s *Store) InsertPolicyVersion(version int, author, note, policyJSON, hash string) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	_, err = tx.Exec(
		`INSERT INTO policy_versions (version, ts, author, note, policy_json, hash) VALUES (?, datetime('now'), ?, ?, ?, ?)`,
		version, author, note, policyJSON, hash,
	)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("insert policy version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit policy version: %w", err)
	}
	return nil
}
