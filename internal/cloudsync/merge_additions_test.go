package cloudsync

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConcurrentCredentialAdditionsDoNotConflict(t *testing.T) {
	e := entry()
	base := NewData()
	base.Entries[e.ID] = e
	a, b := cloneData(base), cloneData(base)
	left, right := a.Entries[e.ID], b.Entries[e.ID]
	c1, c2 := Digest("c1"), Digest("c2")
	a.Credentials[c1] = Credential{Kind: "key"}
	b.Credentials[c2] = Credential{Kind: "key"}
	left.CredentialIDs = []string{c1}
	right.CredentialIDs = []string{c2}
	left.Aliases = append(left.Aliases, "another")
	a.Entries[e.ID] = left
	b.Entries[e.ID] = right
	merged, err := Merge(base, a, b)
	require.NoError(t, err)
	require.Empty(t, merged.Conflicts)
	require.ElementsMatch(t, []string{c1, c2}, merged.Entries[e.ID].CredentialIDs)
	merged.Conflicts[e.ID] = Conflict{Local: &left, Remote: &right}
	require.Equal(t, 1, merged.RepairCompatibleConflicts())
	require.ElementsMatch(t, []string{c1, c2}, merged.Entries[e.ID].CredentialIDs)
	left.Server.Group = "different"
	merged.Conflicts[e.ID] = Conflict{Local: &left, Remote: &right}
	require.Zero(t, merged.RepairCompatibleConflicts())
	require.Len(t, merged.Conflicts, 1)
}
