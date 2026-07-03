package keystore

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBestEffort_PassesThroughOnSuccess proves BestEffort is a no-op when
// StoreAndLoad succeeds: the caller's Result must be returned unchanged.
func TestBestEffort_PassesThroughOnSuccess(t *testing.T) {
	in := Result{Persisted: true, Note: "stored in keychain"}
	got := BestEffort(in, nil)
	require.Equal(t, in, got)
}

// TestBestEffort_DowngradesErrorToNonFatalResult is the core regression test
// for the "gen_key must not hard-fail when the agent/keychain is
// unavailable" fix: a headless Linux host with no ssh-agent makes
// DialAgent (and therefore StoreAndLoad) fail with something like
// "SSH_AUTH_SOCK not set". BestEffort must turn that into a Result with
// Persisted=false and an informative Note — never propagate the error —
// so callers (gen-key CLI, gen_key MCP tool) can continue on to
// WriteRecovery/config update instead of aborting and leaving an orphaned
// key file behind.
func TestBestEffort_DowngradesErrorToNonFatalResult(t *testing.T) {
	err := errors.New("dial agent: SSH_AUTH_SOCK not set (no ssh-agent running)")
	got := BestEffort(Result{Persisted: true, Note: "should be discarded"}, err)

	require.False(t, got.Persisted, "an error path must never report Persisted=true")
	require.Contains(t, got.Note, "not loaded into agent")
	require.Contains(t, got.Note, err.Error(), "the underlying error must be visible in the note")
	require.Contains(t, got.Note, "key is encrypted on disk",
		"the note must reassure the caller the key file itself is fine")
}
