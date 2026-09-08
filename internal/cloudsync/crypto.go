// Package cloudsync implements a client-encrypted, opt-in SSHM vault.
// Neither plaintext vaults nor unlock material are sent to the sync service.
package cloudsync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"io"
	"unicode/utf8"
)

const KDF = "argon2id-64m-t3-p4"
const MaxBlob = 2 * 1024 * 1024

var encoding = base64.RawURLEncoding
var ErrUnlock = errors.New("could not unlock or authenticate vault")

type Envelope struct {
	Version       int    `json:"version"`
	Account       string `json:"account"`
	VaultID       string `json:"vault_id"`
	KDF           string `json:"kdf"`
	Salt          string `json:"salt"`
	WrapNonce     string `json:"wrap_nonce"`
	WrappedKey    string `json:"wrapped_key"`
	RecoveryNonce string `json:"recovery_nonce"`
	RecoveryKey   string `json:"recovery_key"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}
type Snapshot struct {
	Revision     int64  `json:"revision"`
	BaseRevision int64  `json:"base_revision"`
	OperationID  string `json:"operation_id"`
	Blob         string `json:"blob"`
	Signature    string `json:"signature"`
	RootPublic   string `json:"root_public"`
}
type Vault struct {
	Envelope Envelope
	Master   []byte
	Data     Data
}

func RandomID() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return encoding.EncodeToString(b)
}
func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func Wipe(b []byte) { clear(b) }
func derive(key []byte, info string) []byte {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, nil, []byte("sshm-v1/"+info)), out); err != nil {
		panic(err)
	}
	return out
}
func (e Envelope) aad(purpose string) []byte {
	return []byte(fmt.Sprintf("sshm-v1\n%s\n%s\n%s", e.Account, e.VaultID, purpose))
}
func seal(key, plain, aad []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	n := random(g.NonceSize())
	return encoding.EncodeToString(n), encoding.EncodeToString(g.Seal(nil, n, plain, aad)), nil
}
func unseal(key []byte, nonce, ciphertext string, aad []byte) ([]byte, error) {
	n, err := encoding.DecodeString(nonce)
	if err != nil || len(n) != 12 {
		return nil, ErrUnlock
	}
	c, err := encoding.DecodeString(ciphertext)
	if err != nil || len(c) < 16 {
		return nil, ErrUnlock
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnlock
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnlock
	}
	p, err := g.Open(nil, n, c, aad)
	if err != nil {
		return nil, ErrUnlock
	}
	return p, nil
}
func ValidAccountPassword(pass []byte) bool {
	n := utf8.RuneCount(pass)
	return utf8.Valid(pass) && n >= 6 && n <= 256
}

func NewVault(account string, pass []byte) (*Vault, string, error) {
	if !ValidAccount(account) || !utf8.Valid(pass) || utf8.RuneCount(pass) < 6 || len(pass) > 1024 {
		return nil, "", errors.New("use a valid account and an unlock phrase of at least 6 characters")
	}
	v := &Vault{Master: random(32), Data: NewData(), Envelope: Envelope{Version: 1, Account: account, VaultID: RandomID(), KDF: KDF, Salt: encoding.EncodeToString(random(16))}}
	recovery := encoding.EncodeToString(random(32))
	salt, _ := encoding.DecodeString(v.Envelope.Salt)
	kek := argon2.IDKey(pass, salt, 3, 64*1024, 4, 32)
	defer Wipe(kek)
	var err error
	v.Envelope.WrapNonce, v.Envelope.WrappedKey, err = seal(kek, v.Master, v.Envelope.aad("wrap"))
	if err != nil {
		return nil, "", err
	}
	raw, _ := encoding.DecodeString(recovery)
	rk := derive(raw, "recovery-wrap")
	defer Wipe(rk)
	defer Wipe(raw)
	v.Envelope.RecoveryNonce, v.Envelope.RecoveryKey, err = seal(rk, v.Master, v.Envelope.aad("recovery"))
	return v, recovery, err
}
func RecoveryAuth(code string) (string, error) {
	raw, err := encoding.DecodeString(code)
	if err != nil || len(raw) != 32 {
		return "", ErrUnlock
	}
	defer Wipe(raw)
	k := derive(raw, "account-recovery")
	defer Wipe(k)
	return encoding.EncodeToString(k), nil
}
func (v *Vault) private() ed25519.PrivateKey {
	seed := derive(v.Master, "signature")
	defer Wipe(seed)
	return ed25519.NewKeyFromSeed(seed)
}
func (v *Vault) Public() string {
	p := v.private()
	defer Wipe(p)
	return encoding.EncodeToString(p.Public().(ed25519.PublicKey))
}
func syncMessage(account string, base int64, op, blob string) []byte {
	return []byte(fmt.Sprintf("sshm-sync-v1\n%s\n%d\n%s\n%s", account, base, op, blob))
}
func (v *Vault) Snapshot(base int64, op string) (Snapshot, error) {
	if err := v.Data.Validate(); err != nil {
		return Snapshot{}, err
	}
	plain, err := json.Marshal(v.Data)
	if err != nil {
		return Snapshot{}, err
	}
	defer Wipe(plain)
	key := derive(v.Master, "data")
	defer Wipe(key)
	v.Envelope.Nonce, v.Envelope.Ciphertext, err = seal(key, plain, v.Envelope.aad("data"))
	if err != nil {
		return Snapshot{}, err
	}
	blob, err := json.Marshal(v.Envelope)
	if err != nil {
		return Snapshot{}, err
	}
	if len(blob) > MaxBlob {
		return Snapshot{}, errors.New("vault exceeds 2 MiB encrypted limit; no data was uploaded")
	}
	p := v.private()
	defer Wipe(p)
	return Snapshot{BaseRevision: base, OperationID: op, Blob: string(blob), RootPublic: v.Public(), Signature: encoding.EncodeToString(ed25519.Sign(p, syncMessage(v.Envelope.Account, base, op, string(blob))))}, nil
}
func parseEnvelope(account string, s Snapshot) (Envelope, error) {
	var e Envelope
	if s.Revision < 0 || s.BaseRevision < 0 || (s.Revision != 0 && s.Revision != s.BaseRevision+1) {
		return e, ErrUnlock
	}
	if len(s.Blob) > MaxBlob || json.Unmarshal([]byte(s.Blob), &e) != nil || e.Version != 1 || e.Account != account || e.KDF != KDF || !validID(e.VaultID) {
		return e, ErrUnlock
	}
	salt, err := encoding.DecodeString(e.Salt)
	if err != nil || len(salt) != 16 {
		return e, ErrUnlock
	}
	return e, nil
}
func Unlock(account string, s Snapshot, pass []byte, recovery bool) (*Vault, error) {
	e, err := parseEnvelope(account, s)
	if err != nil {
		return nil, err
	}
	var master []byte
	if recovery {
		raw, err := encoding.DecodeString(string(pass))
		if err != nil || len(raw) != 32 {
			return nil, ErrUnlock
		}
		defer Wipe(raw)
		k := derive(raw, "recovery-wrap")
		defer Wipe(k)
		master, err = unseal(k, e.RecoveryNonce, e.RecoveryKey, e.aad("recovery"))
		if err != nil {
			return nil, err
		}
	} else {
		if len(pass) > 1024 {
			return nil, ErrUnlock
		}
		salt, _ := encoding.DecodeString(e.Salt)
		k := argon2.IDKey(pass, salt, 3, 64*1024, 4, 32)
		defer Wipe(k)
		master, err = unseal(k, e.WrapNonce, e.WrappedKey, e.aad("wrap"))
		if err != nil {
			return nil, err
		}
	}
	defer Wipe(master)
	v, err := UnlockMaster(account, s, master)
	return v, err
}
func UnlockMaster(account string, s Snapshot, master []byte) (*Vault, error) {
	e, err := parseEnvelope(account, s)
	if err != nil || len(master) != 32 {
		return nil, ErrUnlock
	}
	v := &Vault{Envelope: e, Master: append([]byte(nil), master...)}
	success := false
	defer func() {
		if !success {
			Wipe(v.Master)
		}
	}()
	pub, _ := encoding.DecodeString(v.Public())
	sig, er := encoding.DecodeString(s.Signature)
	if er != nil || v.Public() != s.RootPublic || !ed25519.Verify(pub, syncMessage(account, s.BaseRevision, s.OperationID, s.Blob), sig) {
		return nil, ErrUnlock
	}
	key := derive(master, "data")
	defer Wipe(key)
	plain, err := unseal(key, e.Nonce, e.Ciphertext, e.aad("data"))
	if err != nil {
		return nil, err
	}
	defer Wipe(plain)
	if json.Unmarshal(plain, &v.Data) != nil || v.Data.Validate() != nil {
		return nil, ErrUnlock
	}
	if v.Data.Hardware == nil {
		v.Data.Hardware = NewData().Hardware
	}
	if v.Data.Activity == nil {
		v.Data.Activity = map[string]Activity{}
	}
	success = true
	return v, nil
}
func Digest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (v *Vault) RotationAuthorization(s Snapshot, recoveryAuth string) string {
	p := v.private()
	defer Wipe(p)
	msg := fmt.Sprintf("sshm-rotate-v1\n%s\n%d\n%s\n%s\n%s", v.Envelope.Account, s.BaseRevision, s.RootPublic, s.Blob, recoveryAuth)
	return encoding.EncodeToString(ed25519.Sign(p, []byte(msg)))
}
