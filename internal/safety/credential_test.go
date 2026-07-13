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
		{name: "token colon question value", value: "token: ?colon-secret", want: true},
		{name: "secret long flag", value: "deploy --secret flag-secret", want: true},
		{name: "API key long flag", value: "deploy --api-key=flag-secret", want: true},
		{name: "client secret long flag", value: "deploy --client-secret flag-secret", want: true},
		{name: "mysql short password flag", value: "mysql -uroot -pmysql-secret database", want: true},
		{name: "mysqldump short password flag", value: "mysqldump -pbackup-secret database", want: true},
		{name: "mysqladmin short password flag", value: "mysqladmin -padmin-secret ping", want: true},
		{name: "mariadb short password flag", value: "mariadb -pmariadb-secret database", want: true},
		{name: "mariadb-dump short password flag", value: "mariadb-dump -pdump-secret database", want: true},
		{name: "sshpass short password flag", value: "sshpass -pssh-secret ssh example.com", want: true},
		{name: "sudo mysql short password flag", value: "sudo mysql -uroot -psudo-secret database", want: true},
		{name: "underscore assignment key", value: "DEPLOY_TOKEN=underscore-secret", want: true},
		{name: "hyphen assignment key", value: "deploy-token=hyphen-secret", want: true},
		{name: "concatenated password key", value: "DBPASSWORD=concatenated-secret", want: true},
		{name: "concatenated passwd key", value: "DBPASSWD=concatenated-secret", want: true},
		{name: "concatenated token key", value: "DEPLOYTOKEN=concatenated-secret", want: true},
		{name: "concatenated secret key", value: "CLIENTSECRET=concatenated-secret", want: true},
		{name: "concatenated API key", value: "SERVICEAPIKEY=concatenated-secret", want: true},
		{name: "terminal key field", value: "SIGNING_KEY=signing-secret", want: true},
		{name: "URL password", value: "https://user:pass@example.com/repo.git", want: true},
		{name: "SSH URL password", value: "ssh://user:ssh-secret@example.com/repo.git", want: true},
		{name: "SFTP URL password", value: "sftp://user:sftp-secret@example.com/path", want: true},
		{name: "Postgres URL password", value: "postgres://user:postgres-secret@example.com/db", want: true},
		{name: "MySQL URL password", value: "mysql://user:mysql-secret@example.com/db", want: true},
		{name: "git HTTPS URL password", value: "git+https://user:git-secret@example.com/repo.git", want: true},
		{name: "GitHub token username userinfo", value: "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@example.com/repo", want: true},
		{name: "token service path", value: "/srv/token-service/releases", want: false},
		{name: "ordinary URL", value: "https://example.com/releases", want: false},
		{name: "HTTP ordinary username userinfo", value: "http://alice@example.com/repo", want: false},
		{name: "HTTPS ordinary username userinfo", value: "https://alice@example.com/repo", want: false},
		{name: "git HTTPS ordinary username userinfo", value: "git+https://alice@example.com/repo", want: false},
		{name: "SSH git username", value: "ssh://git@example.com/repo.git", want: false},
		{name: "ordinary command", value: "go test ./... -count=1", want: false},
		{name: "Go parallel flag", value: "go test -parallel=4 ./...", want: false},
		{name: "port flag", value: "app -port=8080", want: false},
		{name: "profile flag", value: "tool -profile=release", want: false},
		{name: "IPv4 address", value: "https://10.0.0.5/status", want: false},
		{name: "monkey assignment", value: "MONKEY=value", want: false},
		{name: "key path assignment", value: "KEY_PATH=/tmp/signing-key", want: false},
		{name: "key file assignment", value: "KEY_FILE=/tmp/signing-key.pub", want: false},
		{name: "API key path assignment", value: "API_KEY_PATH=/tmp/api-key", want: false},
		{name: "signing key file assignment", value: "SIGNING_KEY_FILE=/tmp/signing-key", want: false},
		{name: "private key file assignment", value: "PRIVATE_KEY_FILE=/tmp/private-key", want: false},
		{name: "hyphenated token key path assignment", value: "DEPLOY-TOKEN-KEY-PATH=/tmp/token-key", want: false},
		{name: "public key assignment", value: "PUBLIC_KEY=/tmp/id_ed25519.pub", want: false},
		{name: "POSIX env reference", value: "TOKEN=$TOKEN deploy", want: false},
		{name: "POSIX braced env reference", value: "TOKEN=${TOKEN} deploy", want: false},
		{name: "PowerShell env reference", value: "TOKEN=$env:TOKEN; deploy", want: false},
		{name: "cmd env reference", value: "TOKEN=%TOKEN% deploy", want: false},
		{name: "flag env reference", value: "deploy --token $TOKEN", want: false},
		{name: "colon env reference", value: "password: ${PASSWORD}", want: false},
		{name: "URI password env reference", value: "postgres://user:$PASSWORD@example.com/db", want: false},
		{name: "HTTPS username env reference", value: "https://$TOKEN@example.com/repo", want: false},
		{name: "HTTPS PowerShell env username", value: "https://$env:TOKEN@example.com/repo", want: false},
		{name: "braced PowerShell env reference", value: "TOKEN=${env:TOKEN} deploy", want: false},
		{name: "required POSIX env reference", value: "TOKEN=${TOKEN:?required} deploy", want: false},
		{name: "hardcoded POSIX default", value: "TOKEN=${TOKEN:-hardcoded} deploy", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ContainsCredentialMaterial(tt.value))
		})
	}
}
