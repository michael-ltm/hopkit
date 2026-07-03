package keys

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomPassphrase_ShapeAndCharset(t *testing.T) {
	p, err := RandomPassphrase()
	require.NoError(t, err)
	require.Len(t, p, 43) // 32 bytes base64url, no padding
	require.Regexp(t, regexp.MustCompile(`^[A-Za-z0-9_-]+$`), p)
}

func TestRandomPassphrase_Unique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		p, err := RandomPassphrase()
		require.NoError(t, err)
		require.False(t, seen[p], "passphrase repeated")
		seen[p] = true
	}
}
