// Package store persists Argus decisions and policy versions to a local
// SQLite database. Writes are best-effort at the caller: the verdict is
// computed before, and independently of, any write here.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// Row is one recorded decision. JSON tags give the web API and the JSONL
// export stable snake_case keys independent of Go field-naming conventions.
type Row struct {
	ID             int    `json:"id"`
	TS             string `json:"ts"`
	Session        string `json:"session"`
	CWD            string `json:"cwd"`
	Tool           string `json:"tool"`
	Command        string `json:"command"`
	File           string `json:"file"`
	Severity       string `json:"severity"`
	Verdict        string `json:"verdict"`
	PermissionMode string `json:"permission_mode"`
	RuleID         string `json:"rule_id"`
	Harness        string `json:"harness"`
	PolicyVersion  int    `json:"policy_version"`
	Obfuscation    bool   `json:"obfuscation"`
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

// rowColumns is the column list (in Row field order) shared by every read
// method below, so the SELECT and the Scan stay in lockstep in one place.
const rowColumns = `id, ts, session, cwd, tool, command, file, severity, verdict, permission_mode, rule_id, harness, policy_version, obfuscation`

// scanRows drains a rowColumns-shaped *sql.Rows into []Row, closing it.
func scanRows(rows *sql.Rows) ([]Row, error) {
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.ID, &r.TS, &r.Session, &r.CWD, &r.Tool, &r.Command, &r.File, &r.Severity, &r.Verdict, &r.PermissionMode, &r.RuleID, &r.Harness, &r.PolicyVersion, &r.Obfuscation); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	return out, nil
}

// Recent returns the most recent decisions, newest first, up to limit.
func (s *Store) Recent(limit int) ([]Row, error) {
	rows, err := s.db.Query(`SELECT `+rowColumns+` FROM decisions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent: %w", err)
	}
	return scanRows(rows)
}

// MaxID returns the highest decision id recorded, or 0 if none exist. The
// SSE stream (Plan 2 Task 8) seeds its cursor from this so it only tails
// decisions inserted after the connection opened.
func (s *Store) MaxID() (int, error) {
	var id int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(id),0) FROM decisions`).Scan(&id); err != nil {
		return 0, fmt.Errorf("max id: %w", err)
	}
	return id, nil
}

// DecisionsAfter returns decisions with id > afterID, oldest first, up to
// limit — the SSE poll loop's incremental read.
func (s *Store) DecisionsAfter(afterID, limit int) ([]Row, error) {
	rows, err := s.db.Query(`SELECT `+rowColumns+` FROM decisions WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("query decisions after: %w", err)
	}
	return scanRows(rows)
}

// Page returns decisions newest first, optionally filtered to one severity
// and/or paged with a cursor: beforeID<=0 starts from the newest row,
// otherwise only ids strictly less than beforeID are returned. An empty
// severity matches all severities.
func (s *Store) Page(severity string, limit, beforeID int) ([]Row, error) {
	query := `SELECT ` + rowColumns + ` FROM decisions`
	var clauses []string
	var args []any
	if severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, severity)
	}
	if beforeID > 0 {
		clauses = append(clauses, "id < ?")
		args = append(args, beforeID)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query page: %w", err)
	}
	return scanRows(rows)
}

// AllDecisions returns decisions oldest first, up to cap rows. When
// claudeCodeOnly is set, only Harness=="claude-code" rows are returned —
// excluding the legacy agent-review import, which was scored by a
// different engine and would corrupt a replay. capped reports whether more
// rows existed than cap allowed through.
func (s *Store) AllDecisions(cap int, claudeCodeOnly bool) (rows []Row, capped bool, err error) {
	query := `SELECT ` + rowColumns + ` FROM decisions`
	var args []any
	if claudeCodeOnly {
		query += ` WHERE harness = ?`
		args = append(args, "claude-code")
	}
	query += ` ORDER BY id ASC LIMIT ?`
	args = append(args, cap+1)

	sqlRows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("query all decisions: %w", err)
	}
	out, err := scanRows(sqlRows)
	if err != nil {
		return nil, false, err
	}
	if len(out) > cap {
		return out[:cap], true, nil
	}
	return out, false, nil
}

// DistinctSessions counts distinct non-empty session ids across all
// history. The empty session (hook events with no session id) is excluded,
// matching the CLI's stats.go behavior.
func (s *Store) DistinctSessions() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT session) FROM decisions WHERE session != ''`).Scan(&n); err != nil {
		return 0, fmt.Errorf("distinct sessions: %w", err)
	}
	return n, nil
}

// VerdictCount reports the full-history count of decisions with the given
// verdict (e.g. "deny").
func (s *Store) VerdictCount(verdict string) (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decisions WHERE verdict = ?`, verdict).Scan(&n); err != nil {
		return 0, fmt.Errorf("verdict count: %w", err)
	}
	return n, nil
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

// VersionMeta is one policy_versions row without the full policy JSON body
// — the audit-trail listing the web policy editor renders.
type VersionMeta struct {
	Version int
	TS      string
	Author  string
	Note    string
	Hash    string
}

// PolicyVersions lists recorded policy snapshots newest first.
func (s *Store) PolicyVersions() ([]VersionMeta, error) {
	rows, err := s.db.Query(`SELECT version, ts, author, note, hash FROM policy_versions ORDER BY version DESC`)
	if err != nil {
		return nil, fmt.Errorf("query policy versions: %w", err)
	}
	defer rows.Close()

	var out []VersionMeta
	for rows.Next() {
		var v VersionMeta
		if err := rows.Scan(&v.Version, &v.TS, &v.Author, &v.Note, &v.Hash); err != nil {
			return nil, fmt.Errorf("scan policy version: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy versions: %w", err)
	}
	return out, nil
}

// PolicyVersionJSON returns the full policy document text recorded for a
// given version, for the "view snapshot" / replay --version path.
func (s *Store) PolicyVersionJSON(version int) (string, error) {
	var j string
	if err := s.db.QueryRow(`SELECT policy_json FROM policy_versions WHERE version = ?`, version).Scan(&j); err != nil {
		return "", fmt.Errorf("policy version json: %w", err)
	}
	return j, nil
}

// Close releases the underlying database handle. Callers (argus serve)
// defer this on shutdown.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}
	return nil
}
