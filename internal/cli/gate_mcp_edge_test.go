package cli

import (
	"strings"
	"testing"
)

// decision extracts the emitted permissionDecision from a gate run, or "" if
// the gate emitted no decision at all (which would itself be a fail-OPEN bug).
func decision(out string) string {
	for _, v := range []string{"deny", "ask", "allow"} {
		if strings.Contains(out, `"permissionDecision":"`+v+`"`) {
			return v
		}
	}
	return ""
}

// TestGateMCPEdgeCases drives the full hot path (parse -> classify -> verdict
// -> emit) end to end over the Phase-4A MCP-gating surface. Every case asserts
// the emitted verdict AND that the gate always emits SOME decision: an empty
// decision is a fail-open, the worst UX the gate can produce (CLAUDE.md §2).
// Home is nonexistent, so policy.Default() applies deterministically.
func TestGateMCPEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // "deny" | "ask" | "allow"
	}{
		// --- Group 1: fail-closed parsing on NON-MCP tools ---
		{"bash_command_wrong_type",
			`{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":123}}`, "deny"},
		{"bash_toolinput_array",
			`{"tool_name":"Bash","tool_input":[1,2]}`, "deny"},
		{"bash_toolinput_absent",
			`{"tool_name":"Bash","permission_mode":"default"}`, "deny"},
		{"write_filepath_wrong_type",
			`{"tool_name":"Write","tool_input":{"file_path":123}}`, "deny"},
		{"invalid_json", `{`, "deny"},
		{"empty_stdin", ``, "deny"},

		// --- Group 2: MCP tolerates arbitrary tool_input, then classifies ---
		{"mcp_delete_ssh_floor",
			`{"tool_name":"mcp__filesystem__delete_file","permission_mode":"default","tool_input":{"path":"/home/x/.ssh/id_rsa"}}`, "deny"},
		{"mcp_copy_aws_creds_floor",
			`{"tool_name":"mcp__fs__copy_file","permission_mode":"default","tool_input":{"src":"/home/x/.aws/credentials","dst":"/tmp/x"}}`, "deny"},
		{"mcp_delete_benign_medium",
			`{"tool_name":"mcp__fs__delete_file","permission_mode":"default","tool_input":{"path":"/tmp/x"}}`, "ask"},
		{"mcp_destructive_sql_medium",
			`{"tool_name":"mcp__db__query","permission_mode":"default","tool_input":{"sql":"DROP TABLE users"}}`, "ask"},
		// Honest-limit (documented): a read tool over a credential path is NOT a
		// floor verb and NOT mutating -> allow. This test PINS that known gap so
		// a future change to close it is a conscious, reviewed decision.
		{"mcp_read_ssh_honest_limit_allow",
			`{"tool_name":"mcp__fs__read_file","permission_mode":"default","tool_input":{"path":"/home/x/.ssh/id_rsa"}}`, "allow"},
		// A non-file-op tool merely mentioning a credential path in freeform args
		// must NOT be floored (the FP the reviews demanded be avoided).
		{"mcp_search_mentions_ssh_not_floored",
			`{"tool_name":"mcp__docs__search","permission_mode":"default","tool_input":{"query":"how do I use ~/.ssh/id_rsa"}}`, "allow"},

		// --- Group 3: MCP with malformed / non-object tool_input (tolerated) ---
		{"mcp_toolinput_array_still_classifies",
			`{"tool_name":"mcp__fs__delete_file","permission_mode":"default","tool_input":[1,2]}`, "ask"},
		{"mcp_command_wrong_type_still_classifies",
			`{"tool_name":"mcp__fs__write_file","permission_mode":"default","tool_input":{"command":123}}`, "ask"},
		{"mcp_toolinput_null",
			`{"tool_name":"mcp__fs__read_file","permission_mode":"default","tool_input":null}`, "allow"},

		// --- Group 4: tool-name boundary / evasion ---
		{"mcp_uppercase_verb_floor",
			`{"tool_name":"mcp__fs__DELETE_FILE","permission_mode":"default","tool_input":{"path":"/home/x/.ssh/id_rsa"}}`, "deny"},
		{"mcp_plugin_form_delete_ssh_floor",
			`{"tool_name":"mcp__plugin_acme_fs__delete_file","permission_mode":"default","tool_input":{"path":"/home/x/.ssh/id_rsa"}}`, "deny"},
		{"mcp_list_updates_safe",
			`{"tool_name":"mcp__fs__list_updates","permission_mode":"default","tool_input":{"a":"b"}}`, "allow"},
		{"mcp_undelete_not_matched",
			`{"tool_name":"mcp__fs__undelete_file","permission_mode":"default","tool_input":{"path":"/tmp/x"}}`, "allow"},
		{"mcp_deletion_noun_not_matched",
			`{"tool_name":"mcp__fs__deletion_report","permission_mode":"default","tool_input":{"a":"b"}}`, "allow"},
		{"mcp_no_tool_segment",
			`{"tool_name":"mcp__server","permission_mode":"default","tool_input":{"path":"/home/x/.ssh/id_rsa"}}`, "allow"},
		{"mcp_empty_after_prefix",
			`{"tool_name":"mcp__","permission_mode":"default","tool_input":{"path":"/home/x/.ssh/id_rsa"}}`, "allow"},
		// A Bash command that merely mentions an mcp__ tool name as text must not
		// fire any mcp rule (Bash cannot satisfy Tool:["mcp"]).
		{"bash_text_mentions_mcp_name_allow",
			`{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"echo mcp__filesystem__delete_file"}}`, "allow"},

		// --- Group 5: acceptEdits floor escalation (medium -> deny) ---
		// In acceptEdits, medium maps to deny, so a mutating MCP tool cannot be
		// auto-accepted without a human.
		{"mcp_mutating_acceptEdits_denies",
			`{"tool_name":"mcp__fs__delete_file","permission_mode":"acceptEdits","tool_input":{"path":"/tmp/x"}}`, "deny"},

		// --- Sanity: Bash hot path unaffected by MCP work ---
		{"bash_sudo_rm_still_denies",
			`{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"sudo rm -rf /"}}`, "deny"},
		{"bash_benign_still_allows",
			`{"tool_name":"Bash","permission_mode":"default","tool_input":{"command":"ls -la"}}`, "allow"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := decision(run(c.in))
			if got == "" {
				t.Fatalf("gate emitted NO decision (fail-open) for %s", c.name)
			}
			if got != c.want {
				t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
			}
		})
	}
}

// TestGateMCPHugeArgsNoHang feeds a very large tool_input to ensure the gate
// stays responsive and never panics on outsized MCP arguments — the payload
// comes from Claude Code, but a pathological one must still fail gracefully.
func TestGateMCPHugeArgsNoHang(t *testing.T) {
	big := strings.Repeat("a", 512*1024)
	in := `{"tool_name":"mcp__fs__read_file","permission_mode":"default","tool_input":{"note":"` + big + `"}}`
	if d := decision(run(in)); d == "" {
		t.Fatal("gate emitted no decision on a huge MCP payload (fail-open)")
	}
}
