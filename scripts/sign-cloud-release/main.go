// Sign only locally built artifacts; private key bytes never reach stdout.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/michael-ltm/sshm/internal/updater"
	"os"
	"path/filepath"
	"time"
)

func main() {
	keyPath := flag.String("key", "", "private signing key file outside repository")
	initialize := flag.Bool("init-key", false, "create a new signing key; never overwrite")
	version := flag.String("version", "0.8.0-cloud-preview.31", "release version")
	dir := flag.String("assets", "cloud/public/downloads", "built downloads")
	flag.Parse()
	if *keyPath == "" {
		panic("--key required")
	}
	if *initialize {
		if e := os.MkdirAll(filepath.Dir(*keyPath), 0700); e != nil {
			panic(e)
		}
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			panic(e)
		}
		f, e := os.OpenFile(*keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			panic(e)
		}
		if _, e = f.Write(priv); e != nil {
			panic(e)
		}
		f.Close()
		fmt.Println(base64.RawURLEncoding.EncodeToString(pub))
		return
	}
	key, e := os.ReadFile(*keyPath)
	if e != nil {
		panic("cannot read signing key")
	}
	defer clear(key)
	if len(key) != 64 {
		panic("invalid signing key")
	}
	now := time.Now()
	r := updater.Release{Protocol: 1, Version: *version, Published: now.Unix(), Expires: now.Add(90 * 24 * time.Hour).Unix()}
	for _, t := range [][2]string{{"darwin", "amd64"}, {"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}} {
		name := "sshm-" + t[0] + "-" + t[1]
		if t[0] == "windows" {
			name += ".exe"
		}
		b, e := os.ReadFile(filepath.Join(*dir, name))
		if e != nil {
			panic(e)
		}
		h := sha256.Sum256(b)
		r.Assets = append(r.Assets, updater.Asset{OS: t[0], Arch: t[1], URL: "https://sshm.yunmini.net/downloads/" + name, SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))})
	}
	payload, e := json.Marshal(r)
	if e != nil {
		panic(e)
	}
	signature := ed25519.Sign(key, payload)
	wire, e := json.Marshal(updater.Signed{Payload: string(payload), Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(*dir, "release.json"), wire, 0644); e != nil {
		panic(e)
	}
	fmt.Println("Signed release", *version)
}
