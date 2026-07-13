package safety

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainsCredentialMaterialDetectsHighConfidenceSecrets(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "token assignment", value: "TOKEN=literal-secret", want: true},
		{name: "password flag", value: "deploy --password literal-secret", want: true},
		{name: "bearer token", value: "Authorization: Bearer literal-secret", want: true},
		{name: "GitHub token", value: "ghp_abcdefghijklmnopqrstuvwxyz0123456789", want: true},
		{name: "URL password", value: "https://user:pass@example.com/repo.git", want: true},
		{name: "token service path", value: "/srv/token-service/releases", want: false},
		{name: "ordinary URL", value: "https://example.com/releases", want: false},
		{name: "ordinary command", value: "go test ./... -count=1", want: false},
		{name: "IPv4 address", value: "https://10.0.0.5/status", want: false},
		{name: "POSIX env reference", value: "TOKEN=$TOKEN deploy", want: false},
		{name: "POSIX braced env reference", value: "TOKEN=${TOKEN} deploy", want: false},
		{name: "PowerShell env reference", value: "TOKEN=$env:TOKEN; deploy", want: false},
		{name: "cmd env reference", value: "TOKEN=%TOKEN% deploy", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ContainsCredentialMaterial(tt.value))
		})
	}
}
