package ssh

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestDialCloudRequiresResolutionBeforeAuth(t *testing.T) {
	_, err := Dial(&config.Server{Host: "target.invalid", User: "user", Auth: config.AuthCloud}, BuildOpts{ConfigPath: filepath.Join(t.TempDir(), "config.toml")})
	require.ErrorContains(t, err, "sshm cloud agent")
}

func TestDialExplicitCloudResolverFailureDoesNotFallBackToLocalIdentity(t *testing.T) {
	server := &config.Server{Host: "target.invalid", User: "user", Auth: config.AuthKey, KeyPath: writeTempKey(t), CloudEntry: "entry"}
	denied := errors.New("browser approval denied")
	_, err := Dial(server, BuildOpts{ResolveCloud: func(*config.Server, BuildOpts) (*config.Server, BuildOpts, func(), error) {
		return nil, BuildOpts{}, nil, denied
	}})
	require.ErrorIs(t, err, denied)
}

func TestDialCloudRejectsUnresolvedResultsAndCleansUp(t *testing.T) {
	denied := errors.New("grant revoked")
	for _, tc := range []struct {
		name   string
		target *config.Server
		err    error
	}{
		{name: "nil"},
		{name: "entry", target: &config.Server{CloudEntry: "entry"}},
		{name: "auth", target: &config.Server{Auth: config.AuthCloud}},
		{name: "denied", err: denied},
		{name: "invalid native", target: &config.Server{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleaned := 0
			_, err := Dial(&config.Server{CloudEntry: "entry"}, BuildOpts{ResolveCloud: func(s *config.Server, o BuildOpts) (*config.Server, BuildOpts, func(), error) {
				return tc.target, o, func() { cleaned++ }, tc.err
			}})
			require.Error(t, err)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			}
			require.Equal(t, 1, cleaned)
		})
	}
}

func TestDialCloudUsesResolvedCredentialsUntilHandshake(t *testing.T) {
	clearSocksEnv(t)
	old := directDialFunc
	t.Cleanup(func() { directDialFunc = old })
	reached := false
	cleaned := false
	directDialFunc = func(addr string, timeout time.Duration) (net.Conn, error) {
		reached = true
		require.Equal(t, "resolved.invalid:2022", addr)
		require.False(t, cleaned)
		return nil, errors.New("transport fixture")
	}
	_, err := Dial(&config.Server{CloudEntry: "entry"}, BuildOpts{ResolveCloud: func(s *config.Server, o BuildOpts) (*config.Server, BuildOpts, func(), error) {
		return &config.Server{Host: "resolved.invalid", Port: 2022, User: "user", Auth: config.AuthPassword}, BuildOpts{Password: "vault-password", Insecure: true}, func() { cleaned = true }, nil
	}})
	require.ErrorContains(t, err, "transport fixture")
	require.True(t, reached)
	require.True(t, cleaned)
}

func TestDialNativeDoesNotInvokeCloudResolver(t *testing.T) {
	_, err := Dial(&config.Server{CloudVault: "published-native"}, BuildOpts{ResolveCloud: func(*config.Server, BuildOpts) (*config.Server, BuildOpts, func(), error) {
		t.Fatal("native target invoked cloud resolver")
		return nil, BuildOpts{}, nil, nil
	}})
	require.ErrorContains(t, err, "user is required")
}

// A real handshake verifies that cleanup runs after password authentication,
// and that the resolved connection remains usable after the resolver releases it.
func TestDialCloudSuccessfulHandshakeReleasesCredentials(t *testing.T) {
	clearSocksEnv(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	signer, _ := hostSigners(t)
	var cleaned atomic.Bool
	serverConfig := &gssh.ServerConfig{PasswordCallback: func(metadata gssh.ConnMetadata, password []byte) (*gssh.Permissions, error) {
		if cleaned.Load() || metadata.User() != "vault-user" || string(password) != "vault-password" {
			return nil, errors.New("invalid or prematurely released credentials")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		server, channels, requests, err := gssh.NewServerConn(conn, serverConfig)
		if err != nil {
			done <- err
			return
		}
		defer server.Close()
		go gssh.DiscardRequests(requests)
		go func() {
			for channel := range channels {
				_ = channel.Reject(gssh.Prohibited, "fixture")
			}
		}()
		done <- server.Wait()
	}()
	target := &config.Server{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, User: "vault-user", Auth: config.AuthPassword}
	cli, err := Dial(&config.Server{CloudEntry: "entry"}, BuildOpts{ResolveCloud: func(*config.Server, BuildOpts) (*config.Server, BuildOpts, func(), error) {
		return target, BuildOpts{Password: "vault-password", Timeout: time.Second}, func() { cleaned.Store(true) }, nil
	}})
	require.NoError(t, err)
	require.True(t, cleaned.Load())
	underlying, err := cli.Underlying()
	require.NoError(t, err)
	_, _, err = underlying.SendRequest("keepalive@openssh.com", true, nil)
	require.NoError(t, err)
	require.NoError(t, cli.Close())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not close")
	}
}

func TestStrictRouteIgnoresProxyEnvironmentForTargetAndJump(t *testing.T) {
	for _, env := range socksEnvVars {
		for _, throughJump := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/jump=%t", env, throughJump), func(t *testing.T) {
				clearSocksEnv(t)
				t.Setenv(env, "socks5://127.0.0.1:1")
				old := directDialFunc
				defer func() { directDialFunc = old }()
				var addresses []string
				directDialFunc = func(addr string, _ time.Duration) (net.Conn, error) {
					addresses = append(addresses, addr)
					return nil, errors.New("fixture stopped")
				}
				target := &config.Server{Host: "target.invalid", User: "user", Auth: config.AuthPassword}
				opts := BuildOpts{StrictRoute: true, Password: "password", Insecure: true, Timeout: time.Millisecond}
				want := "target.invalid:22"
				if throughJump {
					target.ProxyJump = "jump"
					want = "jump.invalid:22"
					opts.ResolveJump = func(string) (*config.Server, BuildOpts, error) {
						return &config.Server{Host: "jump.invalid", User: "user", Auth: config.AuthPassword}, BuildOpts{Password: "jump-password"}, nil
					}
				}
				var err error
				if throughJump {
					_, err = Dial(target, opts)
				} else {
					var kind transportKind
					_, _, kind, err = dialTransportKind(target, opts, time.Millisecond, false)
					require.Equal(t, kindDirect, kind)
				}
				require.Error(t, err)
				require.Equal(t, []string{want}, addresses)
			})
		}
	}
}

func TestStrictRouteNeverFallsBackAfterMissingJump(t *testing.T) {
	for _, cloud := range []bool{false, true} {
		t.Run(fmt.Sprintf("cloud=%t", cloud), func(t *testing.T) {
			clearSocksEnv(t)
			old := directDialFunc
			defer func() { directDialFunc = old }()
			directDialFunc = func(string, time.Duration) (net.Conn, error) {
				t.Error("failed approved jump bypassed with direct dial")
				return nil, errors.New("unexpected direct")
			}
			target := &config.Server{Host: "target.invalid", User: "user", Auth: config.AuthPassword, ProxyJump: "missing"}
			opts := BuildOpts{StrictRoute: true, Password: "password", Insecure: true, ResolveJump: func(string) (*config.Server, BuildOpts, error) {
				return nil, BuildOpts{}, errors.New("missing approved jump")
			}}
			if cloud {
				resolvedOpts := opts
				resolvedOpts.StrictRoute = false // Dial itself enforces strict cloud admission.
				opts = BuildOpts{}
				target = &config.Server{CloudEntry: "entry"}
				// Capture the authenticated target rather than the local binding.
				resolved := &config.Server{Host: "target.invalid", User: "user", Auth: config.AuthPassword, ProxyJump: "missing"}
				opts.ResolveCloud = func(*config.Server, BuildOpts) (*config.Server, BuildOpts, func(), error) {
					return resolved, resolvedOpts, nil, nil
				}
			}
			_, err := Dial(target, opts)
			require.ErrorContains(t, err, "missing approved jump")
		})
	}
}
