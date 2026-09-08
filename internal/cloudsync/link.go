package cloudsync

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

type LinkRequest struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	Secret     string `json:"secret"`
	DeviceID   string `json:"device_id"`
	Label      string `json:"label"`
	Platform   string `json:"platform"`
	AllowShell bool   `json:"allow_shell"`
	Expires    int64  `json:"-"`
	private    *ecdh.PrivateKey
	root       string
}
type LinkGrant struct {
	Version    int    `json:"version"`
	PublicKey  string `json:"public_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func LinkCode(public string) string {
	b, _ := encoding.DecodeString(public)
	h := sha256.Sum256(b)
	s := strings.ToUpper(hex.EncodeToString(h[:6]))
	return s[:4] + "-" + s[4:8] + "-" + s[8:]
}
func linkKey(secret []byte, user, id string) []byte {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte("sshm-link-v1/"+user+"/"+id)), out); err != nil {
		panic(err)
	}
	return out
}
func linkAAD(user, id, public string) []byte {
	return []byte("sshm-link-v1\n" + user + "\n" + id + "\n" + public)
}
func LinkMessage(user string, r *LinkRequest, grant string) []byte {
	return []byte(fmt.Sprintf("sshm-link-v1\n%s\n%s\n%s\n%d\n%s", user, r.ID, r.PublicKey, r.Expires, grant))
}
func NewLinkRequest(device, label, root string, allowShell bool) (*LinkRequest, error) {
	p, err := encoding.DecodeString(root)
	if err != nil || len(p) != ed25519.PublicKeySize {
		return nil, errors.New("a verified --root-public from your unlocked web vault is required")
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if device == "" {
		device = RandomID()
	}
	return &LinkRequest{ID: RandomID(), DeviceID: device, Label: label, Platform: runtime.GOOS, AllowShell: allowShell, PublicKey: encoding.EncodeToString(key.PublicKey().Bytes()), Secret: encoding.EncodeToString(random(32)), private: key, root: root}, nil
}
func (s *State) BeginLink(ctx context.Context, r *LinkRequest) error {
	var response struct {
		Expires int64 `json:"expires"`
	}
	if err := s.Request(ctx, "POST", "/v1/link/start", r, &response); err != nil {
		return err
	}
	r.Expires = response.Expires
	return nil
}
func (s *State) WaitLink(ctx context.Context, r *LinkRequest) (*Vault, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	defer func() { r.private = nil; r.Secret = "" }()
	for {
		var response struct {
			LoginResult
			Status         string `json:"status"`
			Grant          string `json:"grant"`
			Signature      string `json:"signature"`
			RequestExpires int64  `json:"request_expires"`
		}
		if err := s.Request(ctx, "POST", "/v1/link/poll", map[string]string{"id": r.ID, "secret": r.Secret}, &response); err != nil {
			return nil, err
		}
		if response.Status == "approved" {
			if response.DeviceID != r.DeviceID || response.RequestExpires != r.Expires || response.Snapshot.RootPublic != r.root {
				return nil, errors.New("approved device or vault identity differs from the pinned request")
			}
			pub, _ := encoding.DecodeString(r.root)
			signature, _ := encoding.DecodeString(response.Signature)
			if !ed25519.Verify(pub, LinkMessage(s.Username, r, response.Grant), signature) {
				return nil, errors.New("device approval signature is invalid")
			}
			var grant LinkGrant
			if json.Unmarshal([]byte(response.Grant), &grant) != nil || grant.Version != 1 {
				return nil, ErrUnlock
			}
			remoteBytes, err := encoding.DecodeString(grant.PublicKey)
			if err != nil {
				return nil, ErrUnlock
			}
			remote, err := ecdh.P256().NewPublicKey(remoteBytes)
			if err != nil {
				return nil, ErrUnlock
			}
			shared, err := r.private.ECDH(remote)
			if err != nil {
				return nil, ErrUnlock
			}
			key := linkKey(shared, s.Username, r.ID)
			Wipe(shared)
			master, err := unseal(key, grant.Nonce, grant.Ciphertext, linkAAD(s.Username, r.ID, r.PublicKey))
			Wipe(key)
			if err != nil {
				return nil, ErrUnlock
			}
			defer Wipe(master)
			v, err := UnlockMaster(s.Username, response.Snapshot, master)
			if err != nil {
				return nil, err
			}
			s.DeviceID = response.DeviceID
			s.Token = response.Token
			s.Expires = response.Expires
			s.Base = response.Snapshot
			s.Draft = response.Snapshot
			s.Dirty = false
			s.Pending = nil
			return v, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
