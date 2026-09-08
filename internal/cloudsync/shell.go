package cloudsync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type ShellOpen struct {
	Lifetime  string `json:"lifetime,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Type      string `json:"type"`
	Device    string `json:"device"`
	Epoch     string `json:"epoch"`
	Session   string `json:"session"`
	Expires   int64  `json:"expires"`
	Signature string `json:"signature"`
}

func (r ShellOpen) Message(user string) string {
	if r.Lifetime == "connection" {
		return fmt.Sprintf("sshm-shell-v3\n%s\n%s\n%s\n%s\n%d\n%s\nconnection", user, r.Device, r.Epoch, r.Session, r.Expires, r.Mode)
	}
	if r.Mode == "ssh" {
		return fmt.Sprintf("sshm-shell-v2\n%s\n%s\n%s\n%s\n%d\nssh", user, r.Device, r.Epoch, r.Session, r.Expires)
	}
	return fmt.Sprintf("sshm-shell-v1\n%s\n%s\n%s\n%s\n%d", user, r.Device, r.Epoch, r.Session, r.Expires)
}
func (v *Vault) VerifyShell(r ShellOpen, user, device, epoch string) bool {
	if (r.Lifetime != "" && r.Lifetime != "connection") || (r.Mode != "" && r.Mode != "ssh") || r.Device != device || r.Epoch != epoch || r.Expires <= time.Now().UnixMilli() || r.Expires > time.Now().Add(15*time.Minute).UnixMilli() || len(r.Session) < 8 || len(r.Session) > 100 {
		return false
	}
	pub, _ := encoding.DecodeString(v.Public())
	sig, e := encoding.DecodeString(r.Signature)
	return e == nil && ed25519.Verify(pub, []byte(r.Message(user)), sig)
}

type ShellFrame struct {
	Type       string `json:"type"`
	Session    string `json:"session"`
	Seq        uint64 `json:"seq"`
	Ciphertext string `json:"ciphertext"`
}
type ShellPayload struct {
	Target     string `json:"target,omitempty"`
	Credential string `json:"credential,omitempty"`
	Type       string `json:"type"`
	Data       string `json:"data,omitempty"`
	Cols       int    `json:"cols,omitempty"`
	Rows       int    `json:"rows,omitempty"`
}

// Each direction has a distinct key, nonce space and monotonic receive counter.
// Epoch and random session IDs keep keys unique across reconnects.
type ShellCipher struct {
	g                  cipher.AEAD
	session, direction string
	seq                uint64
}

func NewShellCipher(master []byte, user, device, epoch, session, direction string) (*ShellCipher, error) {
	if len(master) != 32 || (direction != "c2a" && direction != "a2c") {
		return nil, errors.New("invalid shell key")
	}
	k := derive(master, "shell/"+user+"/"+device+"/"+epoch+"/"+session+"/"+direction)
	defer Wipe(k)
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	return &ShellCipher{g: g, session: session, direction: direction}, e
}
func (c *ShellCipher) nonce() []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], c.seq)
	return n
}
func (c *ShellCipher) aad() []byte {
	return []byte(fmt.Sprintf("sshm-shell-frame-v1\n%s\n%s\n%d", c.session, c.direction, c.seq))
}
func (c *ShellCipher) Seal(p ShellPayload) (ShellFrame, error) {
	if c.seq >= 1<<32 {
		return ShellFrame{}, errors.New("shell sequence exhausted")
	}
	b, e := json.Marshal(p)
	if e != nil || len(b) > 32768 {
		return ShellFrame{}, errors.New("shell payload too large")
	}
	defer Wipe(b)
	f := ShellFrame{Type: "frame", Session: c.session, Seq: c.seq, Ciphertext: encoding.EncodeToString(c.g.Seal(nil, c.nonce(), b, c.aad()))}
	c.seq++
	return f, nil
}
func (c *ShellCipher) Open(f ShellFrame) (ShellPayload, error) {
	var p ShellPayload
	if f.Type != "frame" || f.Session != c.session || f.Seq != c.seq || f.Seq >= 1<<32 || len(f.Ciphertext) > 60000 {
		return p, errors.New("invalid shell sequence")
	}
	b, e := encoding.DecodeString(f.Ciphertext)
	if e != nil {
		return p, e
	}
	plain, e := c.g.Open(nil, c.nonce(), b, c.aad())
	if e != nil {
		return p, errors.New("shell authentication failed")
	}
	defer Wipe(plain)
	if len(plain) > 32768 || json.Unmarshal(plain, &p) != nil {
		return p, errors.New("invalid shell payload")
	}
	c.seq++
	return p, nil
}
