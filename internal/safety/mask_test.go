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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := MaskSecrets(tc.in)
			require.NotContains(t, out, tc.secret, "raw password must not survive")
			require.Contains(t, out, "***")
		})
	}
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
