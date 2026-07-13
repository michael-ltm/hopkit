package safety

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskSecrets_RedactsIPv4(t *testing.T) {
	out := MaskSecrets("connecting to 203.0.113.42 now")
	require.Contains(t, out, "203.0.*.*")
	require.NotContains(t, out, "203.0.113.42")
}

func TestMaskSecrets_RedactsEnvAssignments(t *testing.T) {
	out := MaskSecrets("DB_PASS=hunter2\nAPI_KEY=abcdef123")
	require.Contains(t, out, "DB_PASS=***")
	require.Contains(t, out, "API_KEY=***")
	require.NotContains(t, out, "hunter2")
	require.NotContains(t, out, "abcdef123")
}

func TestMaskSecrets_RedactsPrivateKeyBlocks(t *testing.T) {
	in := "-----BEGIN OPENSSH PRIVATE KEY-----\nABCDEF\n-----END OPENSSH PRIVATE KEY-----"
	out := MaskSecrets(in)
	require.NotContains(t, out, "ABCDEF")
	require.Contains(t, out, "[redacted private key]")
}

func TestMaskSecrets_LeavesNormalTextAlone(t *testing.T) {
	in := "disk usage is 42% on /dev/sda1"
	require.Equal(t, in, MaskSecrets(in))
}

func TestMaskSecrets_PrivKeyTakesPrecedenceOverEnvAssign(t *testing.T) {
	// A PEM body containing KEY=... text must be replaced wholesale, not
	// partially corrupted by the env-assign pass. This locks in the
	// priv-key-first ordering in MaskSecrets.
	in := "-----BEGIN RSA PRIVATE KEY-----\nKEY=abc\n-----END RSA PRIVATE KEY-----"
	out := MaskSecrets(in)
	require.Equal(t, "[redacted private key]", out)
}

func TestMaskSecrets_RedactsKVSecrets(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		key    string // expected surviving key prefix
		secret string // value that must disappear
	}{
		{"lowercase password=", "password=hunter2", "password=", "hunter2"},
		{"mixed-case Password=", "Password=hunter2", "Password=", "hunter2"},
		{"passwd=", "passwd=swordfish", "passwd=", "swordfish"},
		{"pwd=", "pwd=letmein", "pwd=", "letmein"},
		{"secret=", "secret=topsecretval", "secret=", "topsecretval"},
		{"token=", "token=abc123def456", "token=", "abc123def456"},
		{"api_key=", "api_key=zzzzyyyy1234", "api_key=", "zzzzyyyy1234"},
		{"api-key=", "api-key=zzzzyyyy1234", "api-key=", "zzzzyyyy1234"},
		{"apikey=", "apikey=zzzzyyyy1234", "apikey=", "zzzzyyyy1234"},
		{"access_key=", "access_key=AKIASECRETVAL", "access_key=", "AKIASECRETVAL"},
		{"private_key=", "private_key=somekeymaterial", "private_key=", "somekeymaterial"},
		{"client_secret=", "client_secret=oauthsecretxyz", "client_secret=", "oauthsecretxyz"},
		{"colon form", "PASSWORD: hunter2", "PASSWORD", "hunter2"},
		{"export form", "export TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxx", "TOKEN=", "ghp_xxxxxxxxxxxxxxxxxxxxxxxx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := MaskSecrets(tc.in)
			require.Contains(t, out, "***", "value should be redacted")
			require.NotContains(t, out, tc.secret, "raw secret must not survive")
			require.Contains(t, out, tc.key, "key should be preserved")
		})
	}
}

func TestMaskSecrets_RedactsPasswordFlags(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string
	}{
		{"mysql -ppass", "mysql -uroot -pSuperSecret1 dbname", "SuperSecret1"},
		{"redis -a style -p", "redis-cli -pMyRedisPass ping", "MyRedisPass"},
		{"--password=", "tool --password=topsecret run", "topsecret"},
		{"--password space", "tool --password topsecret run", "topsecret"},
		{"--password quoted space", `tool --password "two word secret" run`, "two word secret"},
		{"--password escaped quote", `tool --password "two \"word\" secret" run`, `two \"word\" secret`},
		{"attached quoted short password", `mysql -uroot -p"two word secret" dbname`, "two word secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := MaskSecrets(tc.in)
			require.NotContains(t, out, tc.secret, "raw password must not survive")
			require.Contains(t, out, "***")
		})
	}
}

func TestMaskSecrets_RedactsCompleteQuotedValuesAndURIPasswords(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		secret string
	}{
		{name: "environment assignment", input: `TOKEN="two word secret" deploy`, secret: "two word secret"},
		{name: "escaped quote environment assignment", input: `TOKEN="two \"word\" secret" deploy`, secret: `two \"word\" secret`},
		{name: "PowerShell environment assignment", input: `$env:DB_PASSWORD = "two word secret"`, secret: "two word secret"},
		{name: "spaced bare environment assignment", input: `DB_PASSWORD = "two word secret"`, secret: "two word secret"},
		{name: "PowerShell escaped quote assignment", input: "$env:TOKEN = \"two `\"word`\" secret\"", secret: "two `\"word`\" secret"},
		{name: "PowerShell escaped single quote assignment", input: `$env:TOKEN = 'two ''word'' secret'`, secret: `two ''word'' secret`},
		{name: "lowercase assignment", input: `password='two word secret' deploy`, secret: "two word secret"},
		{name: "colon value", input: `password: "two word secret"`, secret: "two word secret"},
		{name: "URI password", input: "fetch https://alice:uri-secret@example.com/repo", secret: "uri-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := MaskSecrets(tt.input)
			require.NotContains(t, out, tt.secret)
			require.Contains(t, out, "***")
		})
	}
}

func TestMaskSecrets_RedactsContextualCommandPasswords(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		secret   string
		preserve string
	}{
		{name: "sshpass separated password", input: "sshpass -p sshpass-secret ssh example.com", secret: "sshpass-secret", preserve: "sshpass -p ***"},
		{name: "docker login separated password", input: "docker login -u alice -p docker-secret", secret: "docker-secret", preserve: "docker login -u alice -p ***"},
		{name: "docker global config attached password", input: "docker --config /tmp/cfg login -u alice -pdocker-secret", secret: "docker-secret", preserve: "login -u alice -p***"},
		{name: "curl short user password", input: "curl -u alice:curl-secret https://example.com", secret: "curl-secret", preserve: "curl -u alice:***"},
		{name: "curl attached user password", input: "curl -ualice:curl-secret https://example.com", secret: "curl-secret", preserve: "curl -ualice:***"},
		{name: "curl proxy user password", input: "curl --proxy-user alice:proxy-secret https://example.com", secret: "proxy-secret", preserve: "curl --proxy-user alice:***"},
		{name: "curl attached proxy user password", input: "curl -Ualice:proxy-secret https://example.com", secret: "proxy-secret", preserve: "curl -Ualice:***"},
		{name: "PowerShell quoted curl executable", input: `& 'C:\Program Files\curl\curl.exe' --user alice:literal-secret https://example.com`, secret: "literal-secret", preserve: "--user alice:***"},
		{name: "curl long user password", input: "curl --user alice:curl-secret https://example.com", secret: "curl-secret", preserve: "curl --user alice:***"},
		{name: "curl quoted password with space", input: `curl --user="alice:curl secret" https://example.com`, secret: "curl secret", preserve: `curl --user="alice:***"`},
		{name: "curl quoted password with shell punctuation", input: `curl -u "alice:two word;&secret" https://example.com`, secret: "two word;&secret", preserve: `curl -u "alice:***"`},
		{name: "curl escaped quote password", input: `curl -u "alice:two \"word\" secret" https://example.com`, secret: `two \"word\" secret`, preserve: `curl -u "alice:***"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := MaskSecrets(tt.input)
			require.NotContains(t, out, tt.secret)
			require.Contains(t, out, tt.preserve)
		})
	}
}

func TestMaskSecrets_PreservesPowerShellCurlEnvironmentReferences(t *testing.T) {
	input := `curl --user '${env:CURL_USER}:${env:CURL_PASSWORD}' https://example.com`
	require.Equal(t, input, MaskSecrets(input))
}

func TestMaskSecrets_RedactsTokens(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		token string
	}{
		{"github ghp", "token is ghp_abcdefghijklmnopqrstuvwxyz0123", "ghp_abcdefghijklmnopqrstuvwxyz0123"},
		{"github gho", "auth gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{"aws akia", "AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"},
		{"slack xoxb", "xoxb-not-a-real-slack-token", "xoxb-not-a-real-slack-token"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"},
		{"bearer", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.foo.bar", "eyJhbGciOiJIUzI1NiJ9.foo.bar"},
		{"bearer opaque", "Authorization: Bearer sometoken12345", "sometoken12345"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := MaskSecrets(tc.in)
			require.NotContains(t, out, tc.token, "raw token must not survive")
			require.Contains(t, out, "***")
		})
	}
}

func TestMaskSecrets_RedactsIPv6(t *testing.T) {
	// Full 8-group form.
	in := "connecting to 2001:0db8:85a3:0000:0000:8a2e:0370:7334 now"
	out := MaskSecrets(in)
	require.NotContains(t, out, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	require.Contains(t, out, "***")

	// Compressed :: form.
	in2 := "host fe80::1ff:fe23:4567:890a here"
	out2 := MaskSecrets(in2)
	require.NotContains(t, out2, "fe80::1ff:fe23:4567:890a")

	// Short compressed form (::1, fe80::1, 2001:db8::1).
	in3 := "loopback is ::1"
	out3 := MaskSecrets(in3)
	require.NotContains(t, out3, "::1")
	require.Contains(t, out3, "***")

	in4 := "addr 2001:db8::1 here"
	out4 := MaskSecrets(in4)
	require.NotContains(t, out4, "2001:db8::1")
	require.Contains(t, out4, "***")

	in5 := "link-local fe80::1 here"
	out5 := MaskSecrets(in5)
	require.NotContains(t, out5, "fe80::1")
	require.Contains(t, out5, "***")
}

func TestMaskSecrets_DoesNotMaskMACOrShortHexColon(t *testing.T) {
	// MAC addresses must NOT be redacted (they are not IPv6).
	mac := "interface hw addr 00:11:22:33:44:55"
	outMAC := MaskSecrets(mac)
	require.Contains(t, outMAC, "00:11:22:33:44:55", "MAC address must not be redacted")
	require.NotContains(t, outMAC, "***")

	// Short hex-colon tokens must NOT be redacted.
	short := "token abc:def:123"
	outShort := MaskSecrets(short)
	require.Contains(t, outShort, "abc:def:123", "short hex-colon token must not be redacted")
}

func TestMaskSecrets_DoesNotOverMaskBenignText(t *testing.T) {
	benign := []string{
		"please send a password reset email to the user",
		"the secret to success is hard work",
		"this token of appreciation",
		"my api key insight is below",
		"the time is 12:30 today",
		"see chapter 4: introduction for details",
	}
	for _, in := range benign {
		out := MaskSecrets(in)
		require.Equal(t, in, out, "benign text must be unchanged: %q", in)
	}
}

func TestMaskSecrets_RedactsShellAndSerializedCredentialForms(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		secret string
	}{
		{name: "PowerShell braced environment assignment", input: `${env:TOKEN}='literal-secret'`, secret: "literal-secret"},
		{name: "composite quoted environment reference plus literal", input: `TOKEN="$TOKEN"-literal-secret`, secret: "literal-secret"},
		{name: "POSIX ANSI-C quoted literal", input: `TOKEN=$'two word secret'`, secret: "two word secret"},
		{name: "PowerShell single quoted here-string", input: "$env:TOKEN = @'\nliteral-secret\n'@", secret: "literal-secret"},
		{name: "quoted bearer token", input: `Authorization: Bearer "literal token"`, secret: "literal token"},
		{name: "POSIX assignment prefix before docker", input: `DOCKER_CONFIG=/tmp docker login -u alice -p docker-secret`, secret: "docker-secret"},
		{name: "env prefix before sshpass", input: `env LC_ALL=C sshpass -p ssh-secret ssh example.com`, secret: "ssh-secret"},
		{name: "sudo options before mysql", input: `sudo -n -- mysql -uroot -pmysql-secret database`, secret: "mysql-secret"},
		{name: "cmd wrapper around attached curl credentials", input: `cmd.exe /d /s /c "curl -ualice:cmd-secret https://example.com"`, secret: "cmd-secret"},
		{name: "JSON quoted password key", input: `{"password":"json-secret"}`, secret: "json-secret"},
		{name: "JSON quoted token key", input: `{"token": "json-token"}`, secret: "json-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := MaskSecrets(tt.input)
			require.NotContains(t, out, tt.secret)
			require.Contains(t, out, redaction)
		})
	}
}

func TestMaskSecrets_PreservesSSHPassPromptAndPowerShellTypeOperator(t *testing.T) {
	tests := []string{
		`sshpass -P "Enter Password:" -e ssh example.com`,
		`[System.Management.Automation.LanguagePrimitives]::ConvertTo('value')`,
		`[System.Type]::Add()`,
		`[System.Type]::`,
		`::`,
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			require.Equal(t, input, MaskSecrets(input))
		})
	}
}

func TestMaskSecrets_RedactsIPv6BeforeSentencePunctuation(t *testing.T) {
	out := MaskSecrets("host fe80::1.")
	require.Equal(t, "host ***.", out)
}

func TestMaskSecrets_ReviewExactReproductions(t *testing.T) {
	secretCases := []struct {
		name    string
		input   string
		secrets []string
	}{
		{name: "POSIX composite single quote", input: `TOKEN='alpha'\''bravo charlie'`, secrets: []string{"alpha", "bravo charlie"}},
		{name: "POSIX ANSI-C quote", input: `TOKEN=$'alpha bravo charlie'`, secrets: []string{"alpha bravo charlie"}},
		{name: "PowerShell here-string", input: "$env:TOKEN = @'\nalpha bravo charlie\n'@", secrets: []string{"alpha bravo charlie"}},
		{name: "quoted bearer", input: `Authorization: Bearer "alpha bravo charlie"`, secrets: []string{"alpha bravo charlie"}},
		{name: "docker assignment prefix", input: `DOCKER_CONFIG=/tmp/docker docker login -u alice -p docker-secret`, secrets: []string{"docker-secret"}},
		{name: "sshpass assignment prefix", input: `FOO=bar sshpass -p ssh-secret ssh example.com`, secrets: []string{"ssh-secret"}},
		{name: "docker sudo option prefix", input: `sudo -E docker login -u alice -p docker-secret`, secrets: []string{"docker-secret"}},
		{name: "mysql PATH assignment prefix", input: `PATH=/usr/local/bin:/usr/bin mysql -uroot -pmysql-secret database`, secrets: []string{"mysql-secret"}},
		{name: "cmd curl wrapper", input: `cmd.exe /d /s /c "curl -ualice:cmd-secret https://example.com"`, secrets: []string{"cmd-secret"}},
		{name: "JSON password and token", input: `{"password":"hunter2","token":"literal-token"}`, secrets: []string{"hunter2", "literal-token"}},
	}

	for _, tt := range secretCases {
		t.Run(tt.name, func(t *testing.T) {
			out := MaskSecrets(tt.input)
			for _, secret := range tt.secrets {
				require.NotContains(t, out, secret)
			}
			require.Contains(t, out, redaction)
		})
	}

	preserved := []string{
		`sshpass -P "Enter Password:" -e ssh example.com`,
		`[System.IO.Path]::GetTempPath()`,
		`[System.Type]::`,
		`operator :: remains syntax`,
	}
	for _, input := range preserved {
		t.Run(input, func(t *testing.T) {
			require.Equal(t, input, MaskSecrets(input))
		})
	}

	t.Run("redaction is idempotent", func(t *testing.T) {
		require.Equal(t, `TOKEN=***`, MaskSecrets(`TOKEN=***`))
	})
}
