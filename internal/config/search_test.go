package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSearchServersRanksIntentMetadata(t *testing.T) {
	servers := map[string]*Server{
		"pc-e5": {
			Description: "Windows x64 reverse engineering lab with CDB",
			Tags:        []string{"windows", "dynamic-debug", "cdb"},
		},
		"prod-web": {
			Description: "Linux production web server",
			Tags:        []string{"linux", "production"},
		},
	}

	matches := SearchServers(servers, "windows dynamic-debug")
	require.Len(t, matches, 1)
	require.Equal(t, "pc-e5", matches[0].Alias)
	require.Contains(t, matches[0].MatchedOn, "description")
	require.Contains(t, matches[0].MatchedOn, "tags")
}

func TestSearchServersRequiresEveryTerm(t *testing.T) {
	servers := map[string]*Server{
		"windows-only": {Tags: []string{"windows"}},
	}
	require.Empty(t, SearchServers(servers, "windows ida"))
}

func TestLegacyNotesRemainLocalDescriptionOnly(t *testing.T) {
	servers := map[string]*Server{
		"legacy": {Notes: "macOS signing and iOS debug host"},
	}
	require.Empty(t, SearchServers(servers, "ios debug"), "private notes must not participate in AI discovery")
	require.Equal(t, "macOS signing and iOS debug host", EffectiveDescription(servers["legacy"]))
}

func TestValidateServerMetadataBounds(t *testing.T) {
	require.NoError(t, ValidateServerMetadataBounds("lab", "Windows lab", []string{"windows"}, "reverse", "private local note"))
	require.Error(t, ValidateServerMetadataBounds("lab", "Windows lab", make([]string, MaxTags+1), "reverse", ""))
	require.Error(t, ValidateServerMetadataBounds("lab", "Windows lab", []string{strings.Repeat("x", MaxTagRunes+1)}, "reverse", ""))
}

func TestValidateDescription(t *testing.T) {
	require.NoError(t, ValidateDescription("Windows reverse lab"))
	require.Error(t, ValidateDescription("line one\nline two"))
}
