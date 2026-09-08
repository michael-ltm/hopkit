package cloudsync

import (
	"strings"
	"testing"
)

func TestPasswordCharacterBoundaries(t *testing.T) {
	for _, tc := range []struct {
		pass  string
		valid bool
	}{
		{"abcde", false}, {"abcdef", true}, {"一二三四五", false},
		{"一二三四五六", true}, {"🔑🔑🔑🔑🔑", false}, {"🔑🔑🔑🔑🔑🔑", true},
		{strings.Repeat("a", 256), true}, {strings.Repeat("a", 257), false},
	} {
		if got := ValidAccountPassword([]byte(tc.pass)); got != tc.valid {
			t.Fatalf("account length %d: got %v", len([]rune(tc.pass)), got)
		}
	}
	for _, pass := range []string{"abcde", "一二三四五", "🔑🔑🔑🔑🔑"} {
		if v, _, err := NewVault("test-six", []byte(pass)); err == nil {
			v.Close()
			t.Fatal("accepted five-character unlock phrase")
		}
	}
	for _, pass := range []string{"abcdef", "一二三四五六", "🔑🔑🔑🔑🔑🔑"} {
		v, _, err := NewVault("test-six", []byte(pass))
		if err != nil {
			t.Fatal(err)
		}
		v.Close()
	}
}
