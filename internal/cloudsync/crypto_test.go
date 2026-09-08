package cloudsync

import (
	"encoding/json"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func fixture(t *testing.T) (*Vault, string) {
	t.Helper()
	v, r, e := NewVault("test-account", []byte("test unlock phrase unique"))
	require.NoError(t, e)
	t.Cleanup(v.Close)
	return v, r
}
func TestEncryptionRecoveryAndTampering(t *testing.T) {
	v, recovery := fixture(t)
	v.Data.Credentials[Digest("secret")] = Credential{Kind: "password", Password: "fixture-secret-not-for-cloud"}
	s, err := v.Snapshot(0, RandomID())
	require.NoError(t, err)
	require.NotContains(t, s.Blob, "fixture-secret")
	opened, err := Unlock("test-account", s, []byte("test unlock phrase unique"), false)
	require.NoError(t, err)
	defer opened.Close()
	require.Equal(t, v.Data, opened.Data)
	restored, err := Unlock("test-account", s, []byte(recovery), true)
	require.NoError(t, err)
	restored.Close()
	_, err = Unlock("other-account", s, []byte(recovery), true)
	require.Error(t, err)
	_, err = Unlock("test-account", s, []byte("wrong password phrase"), false)
	require.Error(t, err)
	corrupt := s
	corrupt.Signature = encoding.EncodeToString(make([]byte, 64))
	_, err = Unlock("test-account", corrupt, []byte(recovery), true)
	require.Error(t, err)
	corrupt = s
	corrupt.BaseRevision++
	_, err = Unlock("test-account", corrupt, []byte(recovery), true)
	require.Error(t, err)
	var e Envelope
	require.NoError(t, json.Unmarshal([]byte(s.Blob), &e))
	e.KDF = "argon2id-extreme"
	b, _ := json.Marshal(e)
	corrupt = s
	corrupt.Blob = string(b)
	_, err = Unlock("test-account", corrupt, []byte(recovery), true)
	require.Error(t, err)
	s2, err := v.Snapshot(0, RandomID())
	require.NoError(t, err)
	require.NotEqual(t, s.Blob, s2.Blob)
}
func entry() Entry {
	s := config.Server{Host: "example.invalid", Port: 22, User: "root", Auth: "key"}
	id := EntryID(s)
	return Entry{ID: id, Server: s, Aliases: []string{"server"}, Sources: map[string]Source{}}
}
func cloneData(d Data) Data { b, _ := json.Marshal(d); var x Data; _ = json.Unmarshal(b, &x); return x }
func TestMergeConcurrentEditAndDelete(t *testing.T) {
	e := entry()
	base := NewData()
	base.Entries[e.ID] = e
	local := cloneData(base)
	remote := cloneData(base)
	le := local.Entries[e.ID]
	le.Server.Description = "local edit"
	local.Entries[e.ID] = le
	remote.Remove(e.ID)
	merged, err := Merge(base, local, remote)
	require.NoError(t, err)
	require.Len(t, merged.Conflicts, 1)
	require.Empty(t, merged.Entries)
	_, err = merged.Find(e.ID)
	require.Error(t, err)
	require.NoError(t, merged.Resolve(e.ID, "local"))
	require.False(t, merged.Deleted[e.ID])
	require.Equal(t, "local edit", merged.Entries[e.ID].Server.Description)
}
func TestMergeInitialDuplicatesRetainsCredentialsAndAliases(t *testing.T) {
	e := entry()
	a, b := NewData(), NewData()
	c1, c2 := Digest("c1"), Digest("c2")
	a.Credentials[c1] = Credential{Kind: "key"}
	b.Credentials[c2] = Credential{Kind: "key"}
	e.CredentialIDs = []string{c1}
	a.Entries[e.ID] = e
	e.CredentialIDs = []string{c2}
	e.Aliases = []string{"other-name"}
	e.Server.Description = "other device"
	b.Entries[e.ID] = e
	m, err := Merge(NewData(), a, b)
	require.NoError(t, err)
	require.Len(t, m.Entries, 1)
	require.Len(t, m.Entries[e.ID].CredentialIDs, 2)
	require.Len(t, m.Entries[e.ID].Aliases, 2)
}
func TestDeletedOfflineImportCannotResurrect(t *testing.T) {
	e := entry()
	remote := NewData()
	remote.Deleted[e.ID] = true
	local := NewData()
	local.Entries[e.ID] = e
	m, err := Merge(NewData(), local, remote)
	require.NoError(t, err)
	require.Empty(t, m.Entries)
	require.True(t, m.Deleted[e.ID])
}
func TestURLRejectsCredentialRedirectTargets(t *testing.T) {
	for _, u := range []string{"http://example.com", "https://user:pw@example.com", "https://example.com/path", "https://example.com?key=secret"} {
		require.Error(t, ValidateURL(u))
	}
	require.NoError(t, ValidateURL("http://127.0.0.1:8787"))
	require.NoError(t, ValidateURL(DefaultURL))
}
func TestSecretsNeverAppearInSerializedState(t *testing.T) {
	v, _ := fixture(t)
	v.Data.Credentials[Digest("pw")] = Credential{Kind: "password", Password: "THIS-IS-A-TEST-SECRET"}
	snap, err := v.Snapshot(0, RandomID())
	require.NoError(t, err)
	state := State{Username: "test-account", Base: snap, Draft: snap}
	b, err := json.Marshal(state)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(b), "THIS-IS-A-TEST-SECRET"))
}
func TestResolutionSurvivesNextSync(t *testing.T) {
	e := entry()
	base := NewData()
	base.Deleted[e.ID] = true
	base.Conflicts[e.ID] = Conflict{Local: &e}
	local := cloneData(base)
	require.NoError(t, local.Resolve(e.ID, "local"))
	merged, err := Merge(base, local, cloneData(base))
	require.NoError(t, err)
	require.Contains(t, merged.Entries, e.ID)
	require.Empty(t, merged.Conflicts)
	require.False(t, merged.Deleted[e.ID])
}
