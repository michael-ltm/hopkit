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
		{name: "PEM private key", value: "-----BEGIN PRIVATE KEY-----\nsecret-key-data\n-----END PRIVATE KEY-----", want: true},
		{name: "AWS access key", value: "AKIAIOSFODNN7EXAMPLE", want: true},
		{name: "Slack token", value: "xoxb-1234567890-abcdefghij", want: true},
		{name: "JWT", value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", want: true},
		{name: "password colon", value: "password: colon-secret", want: true},
		{name: "token colon", value: "token: colon-secret", want: true},
		{name: "secret long flag", value: "deploy --secret flag-secret", want: true},
		{name: "API key long flag", value: "deploy --api-key=flag-secret", want: true},
		{name: "client secret long flag", value: "deploy --client-secret flag-secret", want: true},
		{name: "mysql short password flag", value: "mysql -uroot -pmysql-secret database", want: true},
		{name: "underscore assignment key", value: "DEPLOY_TOKEN=underscore-secret", want: true},
		{name: "hyphen assignment key", value: "deploy-token=hyphen-secret", want: true},
		{name: "URL password", value: "https://user:pass@example.com/repo.git", want: true},
		{name: "SSH URL password", value: "ssh://user:ssh-secret@example.com/repo.git", want: true},
		{name: "SFTP URL password", value: "sftp://user:sftp-secret@example.com/path", want: true},
		{name: "Postgres URL password", value: "postgres://user:postgres-secret@example.com/db", want: true},
		{name: "MySQL URL password", value: "mysql://user:mysql-secret@example.com/db", want: true},
		{name: "git HTTPS URL password", value: "git+https://user:git-secret@example.com/repo.git", want: true},
		{name: "HTTP username userinfo", value: "http://credential@example.com/repo", want: true},
		{name: "HTTPS username userinfo", value: "https://credential@example.com/repo", want: true},
		{name: "git HTTPS username userinfo", value: "git+https://credential@example.com/repo", want: true},
		{name: "token service path", value: "/srv/token-service/releases", want: false},
		{name: "ordinary URL", value: "https://example.com/releases", want: false},
		{name: "SSH git username", value: "ssh://git@example.com/repo.git", want: false},
		{name: "ordinary command", value: "go test ./... -count=1", want: false},
		{name: "IPv4 address", value: "https://10.0.0.5/status", want: false},
		{name: "POSIX env reference", value: "TOKEN=$TOKEN deploy", want: false},
		{name: "POSIX braced env reference", value: "TOKEN=${TOKEN} deploy", want: false},
		{name: "PowerShell env reference", value: "TOKEN=$env:TOKEN; deploy", want: false},
		{name: "cmd env reference", value: "TOKEN=%TOKEN% deploy", want: false},
		{name: "flag env reference", value: "deploy --token $TOKEN", want: false},
		{name: "colon env reference", value: "password: ${PASSWORD}", want: false},
		{name: "URI password env reference", value: "postgres://user:$PASSWORD@example.com/db", want: false},
		{name: "HTTPS username env reference", value: "https://$TOKEN@example.com/repo", want: false},
		{name: "HTTPS PowerShell env username", value: "https://$env:TOKEN@example.com/repo", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ContainsCredentialMaterial(tt.value))
		})
	}
}
