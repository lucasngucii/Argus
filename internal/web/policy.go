package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/lucasngucii/argus/internal/policy"
	"github.com/lucasngucii/argus/internal/store"
)

// versionMeta is the API view of a store.VersionMeta with snake_case JSON keys,
// keeping /api/policy consistent with the rest of the JSON surface (the store
// type carries no json tags).
type versionMeta struct {
	Version int    `json:"version"`
	TS      string `json:"ts"`
	Author  string `json:"author"`
	Note    string `json:"note"`
	Hash    string `json:"hash"`
}

// policyGetResponse is the GET /api/policy payload: the current policy.json
// text (for the editor textarea) plus the version audit trail (newest-first).
type policyGetResponse struct {
	JSON     string        `json:"json"`
	Versions []versionMeta `json:"versions"`
}

// handlePolicy routes GET (read current + versions) and PUT (validate, bump
// version, write, snapshot) on /api/policy.
func (srv *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		srv.getPolicy(w, r)
	case http.MethodPut:
		srv.putPolicy(w, r)
	default:
		methodNotAllowed(w)
	}
}

// getPolicy returns the current policy document text and the version list. A
// missing policy.json (before a first edit) returns the marshaled Default() so
// the editor is populated with the baseline rather than empty.
func (srv *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	text, err := srv.currentPolicyText()
	if err != nil {
		serverError(w, "read policy", err)
		return
	}
	metas, err := srv.store.PolicyVersions()
	if err != nil {
		serverError(w, "policy versions", err)
		return
	}
	writeJSON(w, http.StatusOK, policyGetResponse{JSON: text, Versions: toVersionMetas(metas)})
}

// putPolicy is the validate-before-write path. It reads the candidate policy,
// schema-validates it FIRST (on invalid: 400 and policy.json untouched), then
// stamps the document's own version field to maxVersion+1, writes policy.json,
// and records a matching snapshot under that same number — so a decision's
// policy_version (the gate writes pol.Version) always resolves to a snapshot
// and replay --version lines up. The document version is the single source of
// truth; snapshots are never keyed off an independent counter.
func (srv *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		badRequest(w, "read body", err)
		return
	}
	if err := policy.Validate(body); err != nil {
		badRequest(w, "invalid policy", err)
		return
	}
	next, err := srv.persistPolicy(body, r.URL.Query().Get("note"))
	if err != nil {
		serverError(w, "persist policy", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"version": next})
}

// persistPolicy stamps an already-validated policy document to maxVersion+1,
// writes it to policy.json, and records a matching snapshot under that same
// number, returning the new version. It is the shared write path behind PUT
// /api/policy and POST /api/allowlist — the single place the version/audit
// invariant (document version == snapshot version) is enforced. Callers MUST
// policy.Validate the body first (400 on invalid, file untouched); this
// assumes validity.
func (srv *Server) persistPolicy(body []byte, note string) (int, error) {
	next, err := srv.nextVersion()
	if err != nil {
		return 0, err
	}
	stamped, err := stampVersion(body, next)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(srv.policyPath, stamped, 0o644); err != nil {
		return 0, err
	}
	sum := sha256.Sum256(stamped)
	if err := srv.store.InsertPolicyVersion(next, "web", note, string(stamped), hex.EncodeToString(sum[:])); err != nil {
		return 0, err
	}
	return next, nil
}

// getPolicyVersion serves GET /api/policy/versions/{v} — the recorded snapshot
// document for that version, raw. A missing version is a 404.
func (srv *Server) getPolicyVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	vStr := strings.TrimPrefix(r.URL.Path, "/api/policy/versions/")
	v, err := strconv.Atoi(vStr)
	if err != nil {
		badRequest(w, "version", err)
		return
	}
	js, err := srv.store.PolicyVersionJSON(v)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such policy version"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, js)
}

// currentPolicyText returns the policy.json text, or the marshaled Default()
// when the file does not exist yet.
func (srv *Server) currentPolicyText() (string, error) {
	b, err := os.ReadFile(srv.policyPath)
	if errors.Is(err, os.ErrNotExist) {
		def, mErr := json.MarshalIndent(policy.DefaultFile(), "", "  ")
		if mErr != nil {
			return "", mErr
		}
		return string(def), nil
	}
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// nextVersion returns maxVersion+1 from the recorded snapshots (1 when none
// exist). PolicyVersions is ordered version-descending, so the head is the max.
func (srv *Server) nextVersion() (int, error) {
	metas, err := srv.store.PolicyVersions()
	if err != nil {
		return 0, err
	}
	if len(metas) == 0 {
		return 1, nil
	}
	return metas[0].Version + 1, nil
}

// stampVersion sets the document's own version field to v and re-marshals,
// operating on a generic map so no policy field is dropped on the round-trip.
func stampVersion(body []byte, v int) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	doc["version"] = v
	return json.MarshalIndent(doc, "", "  ")
}

// toVersionMetas maps store rows to the snake_case API view.
func toVersionMetas(in []store.VersionMeta) []versionMeta {
	out := make([]versionMeta, 0, len(in))
	for _, m := range in {
		out = append(out, versionMeta{
			Version: m.Version,
			TS:      m.TS,
			Author:  m.Author,
			Note:    m.Note,
			Hash:    m.Hash,
		})
	}
	return out
}
