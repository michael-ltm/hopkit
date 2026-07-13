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
		{name: "escaped quote token assignment", value: `TOKEN="two \"word\" secret" deploy`, want: true},
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
		{name: "secret assignment resembling BuildKit reference", value: "SECRET=id=SECRET_TOKEN", want: true},
		{name: "API key long flag", value: "deploy --api-key=flag-secret", want: true},
		{name: "client secret long flag", value: "deploy --client-secret flag-secret", want: true},
		{name: "curl short user password flag", value: "curl -u alice:curl-secret https://example.com", want: true},
		{name: "curl long user password flag", value: "curl --user alice:curl-secret https://example.com", want: true},
		{name: "curl equals quoted user password flag", value: `curl --user="alice:curl secret" https://example.com`, want: true},
		{name: "curl escaped quote user password flag", value: `curl --user="alice:two \"word\" secret" https://example.com`, want: true},
		{name: "curl attached user password flag", value: "curl -ualice:attached-secret https://example.com", want: true},
		{name: "curl attached quoted user password flag", value: `curl -u"alice:quoted-secret" https://example.com`, want: true},
		{name: "curl proxy user password flag", value: "curl --proxy-user alice:proxy-secret https://example.com", want: true},
		{name: "curl attached proxy user password flag", value: "curl -Ualice:proxy-secret https://example.com", want: true},
		{name: "PowerShell quoted curl executable password", value: `& 'C:\Program Files\curl\curl.exe' --user alice:literal-secret https://example.com`, want: true},
		{name: "docker build literal secret", value: "docker build --secret literal-secret .", want: true},
		{name: "mysql short password flag", value: "mysql -uroot -pmysql-secret database", want: true},
		{name: "mysqldump short password flag", value: "mysqldump -pbackup-secret database", want: true},
		{name: "mysqladmin short password flag", value: "mysqladmin -padmin-secret ping", want: true},
		{name: "mariadb short password flag", value: "mariadb -pmariadb-secret database", want: true},
		{name: "mariadb-dump short password flag", value: "mariadb-dump -pdump-secret database", want: true},
		{name: "sshpass short password flag", value: "sshpass -pssh-secret ssh example.com", want: true},
		{name: "sshpass separated password flag", value: "sshpass -p literal-secret ssh example.com", want: true},
		{name: "docker login separated password flag", value: "docker login -u alice -p docker-secret", want: true},
		{name: "docker login attached password flag", value: "docker login -u alice -pdocker-secret", want: true},
		{name: "docker global config login password", value: "docker --config /tmp/cfg login -u alice -p docker-secret", want: true},
		{name: "PowerShell quoted docker executable password", value: `& 'C:\Program Files\Docker\docker.exe' login -u alice -p docker-secret`, want: true},
		{name: "PowerShell quoted sshpass executable password", value: `& 'C:\Program Files\sshpass\sshpass.exe' -p ssh-secret ssh example.com`, want: true},
		{name: "PowerShell quoted mysql executable password", value: `& 'C:\Program Files\MySQL\mysql.exe' -uroot -pmysql-secret database`, want: true},
		{name: "sudo mysql short password flag", value: "sudo mysql -uroot -psudo-secret database", want: true},
		{name: "multiline mysql short password flag", value: "echo preflight\nmysql -uroot -pmultiline-secret database", want: true},
		{name: "subshell mysql short password flag", value: "(mysql -uroot -psubshell-secret database)", want: true},
		{name: "underscore assignment key", value: "DEPLOY_TOKEN=underscore-secret", want: true},
		{name: "hyphen assignment key", value: "deploy-token=hyphen-secret", want: true},
		{name: "concatenated pass key", value: "DBPASS=dbpass-secret", want: true},
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
		{name: "URL-like short flag", value: "tool -url=https://example.com", want: false},
		{name: "update short flag", value: "tool -update=scheme:value", want: false},
		{name: "mysql password prompt before database", value: "mysql -uroot -p database", want: false},
		{name: "curl username only", value: "curl -u alice https://example.com", want: false},
		{name: "docker password stdin", value: "docker login --password-stdin registry.example.com", want: false},
		{name: "IPv4 address", value: "https://10.0.0.5/status", want: false},
		{name: "monkey assignment", value: "MONKEY=value", want: false},
		{name: "compass assignment", value: "COMPASS=value", want: false},
		{name: "bypass assignment", value: "BYPASS=value", want: false},
		{name: "ambiguous release key assignment", value: "KEY=release", want: false},
		{name: "ambiguous literal key assignment", value: "KEY=bare-key-secret", want: false},
		{name: "key path assignment", value: "KEY_PATH=/tmp/signing-key", want: false},
		{name: "key file assignment", value: "KEY_FILE=/tmp/signing-key.pub", want: false},
		{name: "API key path assignment", value: "API_KEY_PATH=/tmp/api-key", want: false},
		{name: "signing key file assignment", value: "SIGNING_KEY_FILE=/tmp/signing-key", want: false},
		{name: "private key file assignment", value: "PRIVATE_KEY_FILE=/tmp/private-key", want: false},
		{name: "hyphenated token key path assignment", value: "DEPLOY-TOKEN-KEY-PATH=/tmp/token-key", want: false},
		{name: "token file assignment", value: "TOKEN_FILE=/run/secrets/token", want: false},
		{name: "password file assignment", value: "PASSWORD_FILE=/run/secrets/password", want: false},
		{name: "secret path assignment", value: "SECRET_PATH=/run/secrets/secret", want: false},
		{name: "public key assignment", value: "PUBLIC_KEY=/tmp/id_ed25519.pub", want: false},
		{name: "POSIX env reference", value: "TOKEN=$TOKEN deploy", want: false},
		{name: "POSIX braced env reference", value: "TOKEN=${TOKEN} deploy", want: false},
		{name: "PowerShell env reference", value: "TOKEN=$env:TOKEN; deploy", want: false},
		{name: "cmd env reference", value: "TOKEN=%TOKEN% deploy", want: false},
		{name: "flag env reference", value: "deploy --token $TOKEN", want: false},
		{name: "mysql short password env reference", value: "mysql -p$MYSQL_PASSWORD database", want: false},
		{name: "sshpass separated password env reference", value: "sshpass -p $SSHPASS ssh example.com", want: false},
		{name: "docker login password env reference", value: "docker login -u alice -p $DOCKER_PASSWORD", want: false},
		{name: "curl short user password env reference", value: "curl -u alice:$CURL_PASSWORD https://example.com", want: false},
		{name: "curl long user password env reference", value: "curl --user alice:${CURL_PASSWORD} https://example.com", want: false},
		{name: "curl attached user password env reference", value: "curl -ualice:$CURL_PASSWORD https://example.com", want: false},
		{name: "curl proxy user password env reference", value: "curl --proxy-user alice:$PROXY_PASSWORD https://example.com", want: false},
		{name: "curl PowerShell user password env references", value: `curl --user '${env:CURL_USER}:${env:CURL_PASSWORD}' https://example.com`, want: false},
		{name: "colon env reference", value: "password: ${PASSWORD}", want: false},
		{name: "URI password env reference", value: "postgres://user:$PASSWORD@example.com/db", want: false},
		{name: "HTTPS username env reference", value: "https://$TOKEN@example.com/repo", want: false},
		{name: "HTTPS PowerShell env username", value: "https://$env:TOKEN@example.com/repo", want: false},
		{name: "braced PowerShell env reference", value: "TOKEN=${env:TOKEN} deploy", want: false},
		{name: "required POSIX env reference", value: "TOKEN=${TOKEN:?required} deploy", want: false},
		{name: "hardcoded POSIX default", value: "TOKEN=${TOKEN:-hardcoded} deploy", want: true},
		{name: "token file flag", value: "deploy --token-file /run/secrets/token", want: false},
		{name: "secret file flag", value: "deploy --secret-file=/run/secrets/secret", want: false},
		{name: "Docker BuildKit secret source", value: "docker build --secret id=npmrc,src=/run/secrets/npmrc .", want: false},
		{name: "Docker BuildKit secret environment", value: "docker build --secret id=npmrc,env=NPM_TOKEN .", want: false},
		{name: "Docker BuildKit inferred environment", value: "docker buildx build --secret id=SECRET_TOKEN .", want: false},
		{name: "Docker BuildKit reordered inferred environment", value: "docker buildx build --secret type=env,id=SECRET_TOKEN .", want: false},
		{name: "Docker BuildKit default file reference", value: "docker build --secret id=aws-key .", want: false},
		{name: "Docker BuildKit explicit file reference", value: "docker build --secret type=file,id=aws .", want: false},
		{name: "Docker BuildKit source alias", value: "docker build --secret source=/run/secrets/npmrc,id=npmrc .", want: false},
		{name: "Docker BuildKit mixed literal secret", value: "docker build --secret id=npmrc,src=/run/secrets/npmrc,password=literal-secret .", want: true},
		{name: "mysql uppercase port flag", value: "mysql -P3306 database", want: false},
		{name: "sshpass prompt indicator", value: "sshpass -P Password: -e ssh example.com", want: false},
		{name: "PowerShell quoted sshpass prompt indicator", value: `& 'C:\Program Files\sshpass\sshpass.exe' -P Password: -e ssh example.com`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ContainsCredentialMaterial(tt.value))
		})
	}
}

func TestContainsCredentialMaterialHandlesShellAndSerializedCredentialForms(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "PowerShell braced environment assignment with literal", value: `${env:TOKEN}='literal-secret'`, want: true},
		{name: "composite quoted environment reference plus literal", value: `TOKEN="$TOKEN"-literal-secret`, want: true},
		{name: "POSIX ANSI-C quoted literal", value: `TOKEN=$'two word secret'`, want: true},
		{name: "PowerShell single quoted here-string", value: "$env:TOKEN = @'\nliteral-secret\n'@", want: true},
		{name: "quoted bearer token", value: `Authorization: Bearer "literal token"`, want: true},
		{name: "POSIX assignment prefix before docker", value: `DOCKER_CONFIG=/tmp docker login -u alice -p docker-secret`, want: true},
		{name: "env prefix before sshpass", value: `env LC_ALL=C sshpass -p ssh-secret ssh example.com`, want: true},
		{name: "sudo options before mysql", value: `sudo -n -- mysql -uroot -pmysql-secret database`, want: true},
		{name: "cmd wrapper around attached curl credentials", value: `cmd.exe /d /s /c "curl -ualice:cmd-secret https://example.com"`, want: true},
		{name: "JSON quoted password key", value: `{"password":"json-secret"}`, want: true},
		{name: "JSON quoted token key", value: `{"token": "json-token"}`, want: true},
		{name: "sshpass quoted prompt with environment password", value: `sshpass -P "Enter Password:" -e ssh example.com`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ContainsCredentialMaterial(tt.value))
		})
	}
}

func TestContainsCredentialMaterialReviewExactReproductions(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "POSIX composite single quote", value: `TOKEN='alpha'\''bravo charlie'`, want: true},
		{name: "POSIX ANSI-C quote", value: `TOKEN=$'alpha bravo charlie'`, want: true},
		{name: "PowerShell here-string", value: "$env:TOKEN = @'\nalpha bravo charlie\n'@", want: true},
		{name: "quoted bearer", value: `Authorization: Bearer "alpha bravo charlie"`, want: true},
		{name: "sshpass prompt", value: `sshpass -P "Enter Password:" -e ssh example.com`, want: false},
		{name: "docker assignment prefix", value: `DOCKER_CONFIG=/tmp/docker docker login -u alice -p docker-secret`, want: true},
		{name: "sshpass assignment prefix", value: `FOO=bar sshpass -p ssh-secret ssh example.com`, want: true},
		{name: "docker sudo option prefix", value: `sudo -E docker login -u alice -p docker-secret`, want: true},
		{name: "mysql PATH assignment prefix", value: `PATH=/usr/local/bin:/usr/bin mysql -uroot -pmysql-secret database`, want: true},
		{name: "cmd curl wrapper", value: `cmd.exe /d /s /c "curl -ualice:cmd-secret https://example.com"`, want: true},
		{name: "JSON password and token", value: `{"password":"hunter2","token":"literal-token"}`, want: true},
		{name: "PowerShell static member operator", value: `[System.IO.Path]::GetTempPath()`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ContainsCredentialMaterial(tt.value))
		})
	}
}
