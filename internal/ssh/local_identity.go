package ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const maxLocalIdentityCacheSize = 64 << 10

type localIdentityCache struct {
	PublicKeys []string `json:"public_keys"`
}

// StoreLocalAgentIdentities records only public keys for one exact SSH route
// and cloud binding. The cache lets another local process select an already
// unlocked agent identity without persisting private key material.
func StoreLocalAgentIdentities(configPath string, server *config.Server, pubs []gssh.PublicKey) error {
	path, err := localIdentityCachePath(configPath, server)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(pubs))
	for _, pub := range pubs {
		parsed, err := validateLocalPublicKey(pub)
		if err != nil {
			return err
		}
		keys = append(keys, strings.TrimSpace(string(gssh.MarshalAuthorizedKey(parsed))))
	}
	data, err := json.Marshal(localIdentityCache{PublicKeys: keys})
	if err != nil {
		return fmt.Errorf("encode local identity cache: %w", err)
	}
	if len(data) > maxLocalIdentityCacheSize {
		return errors.New("local identity cache is too large")
	}
	if err := ensurePrivateCacheDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing symlink local identity cache target")
		}
		if !info.Mode().IsRegular() {
			return errors.New("refusing non-regular local identity cache target")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect local identity cache: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create local identity cache: %w", err)
	}
	tmpPath := tmp.Name()
	removeTmp := true
	defer func() {
		_ = tmp.Close()
		if removeTmp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("protect local identity cache: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write local identity cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync local identity cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close local identity cache: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install local identity cache: %w", err)
	}
	removeTmp = false
	return nil
}

// HasLocalAuth checks the same signer path used by BuildClientConfig and
// releases any agent connection opened during the probe.
func HasLocalAuth(server *config.Server, opts BuildOpts) bool {
	if server == nil {
		return false
	}
	if server.Auth == config.AuthAgent {
		// agentAuth defers listing until handshake; a reachable empty agent
		// must not suppress the CLI's interactive vault fallback.
		conn, err := dialAgent()
		if err != nil {
			return false
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return false
		}
		signers, err := agent.NewClient(conn).Signers()
		return err == nil && len(signers) > 0
	}
	_, closer, err := buildAuth(server, opts)
	if closer != nil {
		_ = closer.Close()
	}
	return err == nil
}

func localIdentityCachePath(configPath string, server *config.Server) (string, error) {
	if server == nil {
		return "", errors.New("SSH target is required")
	}
	if configPath == "" {
		configPath = config.ConfigPath()
	}
	port := server.Port
	if port == 0 {
		port = 22
	}
	route, err := json.Marshal(struct {
		Host, User, Jump, Command, Proxy, Entry, Vault string
		Port                                           int
		Forwards                                       []string
	}{
		Host:     server.Host,
		User:     server.User,
		Jump:     server.ProxyJump,
		Command:  server.ProxyCommand,
		Proxy:    server.Proxy,
		Entry:    server.CloudEntry,
		Vault:    server.CloudVault,
		Port:     port,
		Forwards: server.Forwards,
	})
	if err != nil {
		return "", fmt.Errorf("encode local identity route: %w", err)
	}
	sum := sha256.Sum256(route)
	return filepath.Join(filepath.Dir(configPath), "local-identities", hex.EncodeToString(sum[:])+".json"), nil
}

func ensurePrivateCacheDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return fmt.Errorf("create local identity cache parent: %w", err)
	}
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing symlink local identity cache directory")
		}
		if !info.IsDir() {
			return errors.New("local identity cache path is not a directory")
		}
	} else if os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("create local identity cache directory: %w", err)
		}
	} else {
		return fmt.Errorf("inspect local identity cache directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect local identity cache directory: %w", err)
	}
	return nil
}

func validateLocalPublicKey(pub gssh.PublicKey) (gssh.PublicKey, error) {
	if pub == nil {
		return nil, errors.New("invalid public key")
	}
	encoded := gssh.MarshalAuthorizedKey(pub)
	parsed, _, options, rest, err := gssh.ParseAuthorizedKey(encoded)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(parsed.Marshal(), pub.Marshal()) {
		return nil, errors.New("invalid public key")
	}
	return parsed, nil
}

func loadLocalAgentSigners(configPath string, server *config.Server) ([]gssh.Signer, io.Closer, error) {
	path, err := localIdentityCachePath(configPath, server)
	if err != nil {
		return nil, nil, err
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("refusing symlink local identity cache directory")
	}
	if !dirInfo.IsDir() {
		return nil, nil, errors.New("local identity cache path is not a directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("refusing symlink local identity cache target")
	}
	if !info.Mode().IsRegular() || info.Size() > maxLocalIdentityCacheSize {
		return nil, nil, errors.New("invalid local identity cache file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, nil, errors.New("local identity cache changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLocalIdentityCacheSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxLocalIdentityCacheSize {
		return nil, nil, errors.New("local identity cache is too large")
	}
	var cached localIdentityCache
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cached); err != nil {
		return nil, nil, errors.New("invalid local identity cache")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, nil, errors.New("invalid local identity cache")
	}
	if len(cached.PublicKeys) == 0 {
		return nil, nil, errors.New("local identity cache contains no public keys")
	}

	var signers []gssh.Signer
	var closers []io.Closer
	for _, encoded := range cached.PublicKeys {
		pub, _, options, rest, err := gssh.ParseAuthorizedKey([]byte(encoded))
		if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			if closer := closeAll(closers); closer != nil {
				_ = closer.Close()
			}
			return nil, nil, errors.New("invalid public key in local identity cache")
		}
		signer, closer, err := agentSignerFor(pub)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
		closers = append(closers, closer)
	}
	if len(signers) == 0 {
		return nil, nil, errors.New("ssh-agent holds no cached identity")
	}
	return signers, closeAll(closers), nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return err
}
