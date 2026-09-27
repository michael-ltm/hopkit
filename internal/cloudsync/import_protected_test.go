package cloudsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func protectedImportFixture(t *testing.T) (*config.Config, *localstore.Store, localstore.Credential, gssh.PublicKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	store := localstore.New(path)
	store.Protector = testutil.NewDeviceProtector()
	_, raw, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pass := []byte(RandomID())
	block, err := gssh.MarshalPrivateKeyWithPassphrase(raw, "synthetic-generated", pass)
	require.NoError(t, err)
	c := localstore.Credential{Key: pem.EncodeToMemory(block), Passphrase: pass}
	t.Cleanup(func() { localstore.CloseCredentials([]localstore.Credential{c}) })
	keypath := filepath.Join(filepath.Dir(path), "generated-key")
	require.NoError(t, os.WriteFile(keypath, c.Key, 0600))
	cfg := config.New()
	cfg.Servers["generated"] = &config.Server{Host: "synthetic.invalid", Port: 22, User: "ops", Auth: config.AuthKey, KeyPath: keypath}
	require.NoError(t, store.RememberKeyFile(context.Background(), keypath, c))
	signer, err := c.Signer()
	require.NoError(t, err)
	return cfg, store, c, signer.PublicKey()
}

func TestImportProtectedOwnPublishedNativeRecordAndCloudActivity(t *testing.T) {
	ctx := context.Background()
	cfg, store, _, _ := protectedImportFixture(t)
	state := &State{URL: "https://synthetic.invalid", Username: "synthetic-user", Base: Snapshot{RootPublic: "synthetic-root"}}
	owner := InventoryIdentity(state)
	data := NewData()
	defer data.Close()
	report, err := data.ImportProtected(ctx, cfg, "synthetic-device", true, store, owner)
	require.NoError(t, err)
	require.Equal(t, 1, report.Keys)
	require.NoError(t, config.Save(store.ConfigPath, cfg))
	_, err = PublishInventory(store.ConfigPath, state, data)
	require.NoError(t, err)
	cfg, err = config.Load(store.ConfigPath)
	require.NoError(t, err)
	require.Empty(t, cfg.Servers["generated"].CloudEntry)
	require.Equal(t, owner, cfg.Servers["generated"].CloudVault)
	report, err = data.ImportProtected(ctx, cfg, "synthetic-device", true, store, owner)
	require.NoError(t, err)
	require.Equal(t, 1, report.Existing)
	require.Equal(t, 1, report.Keys)
	require.Len(t, data.Credentials, 1)
	// A later generated-key rotation also carries its new locally protected
	// passphrase after PublishInventory has tagged the native target's owner.
	_, rotated, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pass := []byte(RandomID())
	block, err := gssh.MarshalPrivateKeyWithPassphrase(rotated, "synthetic-rotation", pass)
	require.NoError(t, err)
	rotatedCredential := localstore.Credential{Key: pem.EncodeToMemory(block), Passphrase: pass}
	defer localstore.CloseCredentials([]localstore.Credential{rotatedCredential})
	require.NoError(t, os.WriteFile(cfg.Servers["generated"].KeyPath, rotatedCredential.Key, 0600))
	require.NoError(t, store.RememberKeyFile(ctx, cfg.Servers["generated"].KeyPath, rotatedCredential))
	report, err = data.ImportProtected(ctx, cfg, "synthetic-device", true, store, owner)
	require.NoError(t, err)
	require.Equal(t, 1, report.Keys)
	var recoveredRotation bool
	for _, credential := range data.Credentials {
		if string(credential.Passphrase) == string(pass) {
			recoveredRotation = true
		}
	}
	require.True(t, recoveredRotation)
	entry, err := data.Find("generated")
	require.NoError(t, err)
	bound := entry.Server
	bound.Auth, bound.CloudEntry, bound.CloudVault = config.AuthCloud, entry.ID, owner
	bound.LastUsed = time.Now().Add(-time.Minute)
	cfg.Servers = map[string]*config.Server{"published-marker": &bound}
	report, err = data.ImportProtected(ctx, cfg, "synthetic-device", false, store, owner)
	require.NoError(t, err)
	require.Zero(t, report.Keys)
	require.Equal(t, bound.LastUsed.UnixMilli(), data.Activity[entry.ID].LastConnected)
	bound.CloudVault = "foreign-owner"
	bound.LastUsed = time.Now()
	_, err = data.ImportProtected(ctx, cfg, "synthetic-device", false, store, owner)
	require.NoError(t, err)
	require.NotEqual(t, bound.LastUsed.UnixMilli(), data.Activity[entry.ID].LastConnected)
}

func TestImportProtectedInactiveCredentialNeverFallsBackToKeyfile(t *testing.T) {
	cfg, store, _, _ := protectedImportFixture(t)
	require.NoError(t, store.Disable(context.Background(), cfg.Servers["generated"]))
	data := NewData()
	report, err := data.ImportProtected(context.Background(), cfg, "synthetic-device", true, store, "")
	require.NoError(t, err)
	require.Equal(t, 1, report.SkippedDeleted)
	require.Empty(t, data.Entries)
	require.Empty(t, data.Credentials)
}

func TestImportProtectedEncryptedGeneratedKeySnapshotFreshDevice(t *testing.T) {
	ctx := context.Background()
	cfg, store, c, public := protectedImportFixture(t)
	keyBefore, err := os.ReadFile(cfg.Servers["generated"].KeyPath)
	require.NoError(t, err)
	storeBefore, err := os.ReadFile(store.Path())
	require.NoError(t, err)
	require.NoFileExists(t, cfg.Servers["generated"].KeyPath+".passphrase")
	vault, _, err := NewVault("synthetic-user", []byte("synthetic-unlock"))
	require.NoError(t, err)
	defer vault.Close()
	// Legacy import remains compatible and exposes the previously unusable copy.
	old, err := vault.Data.Import(cfg, "synthetic-device", true)
	require.NoError(t, err)
	require.Equal(t, 1, old.LockedKeys)
	report, err := vault.Data.ImportProtected(ctx, cfg, "synthetic-device", true, store, "")
	require.NoError(t, err)
	require.Equal(t, 1, report.Keys)
	require.Zero(t, report.LockedKeys)
	require.Len(t, vault.Data.Credentials, 1)
	entry, err := vault.Data.Find("generated")
	require.NoError(t, err)
	require.Len(t, entry.CredentialIDs, 1)
	imported := vault.Data.Credentials[entry.CredentialIDs[0]]
	require.Equal(t, c.Passphrase, imported.Passphrase)
	require.Equal(t, gssh.FingerprintSHA256(public), imported.Fingerprint)
	snapshot, err := vault.Snapshot(0, RandomID())
	require.NoError(t, err)
	require.NotContains(t, snapshot.Blob, "PRIVATE KEY")
	require.NotContains(t, snapshot.Blob, string(c.Passphrase))
	restored, err := Unlock("synthetic-user", snapshot, []byte("synthetic-unlock"), false)
	require.NoError(t, err)
	defer restored.Close()
	state := &State{URL: "https://synthetic.invalid", Username: "synthetic-user", Base: snapshot}
	freshCfg := config.New()
	target := entry.Server
	target.Auth = config.AuthCloud
	target.CloudEntry = entry.ID
	target.CloudVault = InventoryIdentity(state)
	freshCfg.Servers["new-device"] = &target
	fresh := localstore.New(filepath.Join(t.TempDir(), "new-device.toml"))
	fresh.Protector = testutil.NewDeviceProtector()
	loaded, err := RememberVault(ctx, state, restored, freshCfg, fresh)
	require.NoError(t, err)
	require.Equal(t, 1, loaded.Loaded)
	cs, err := fresh.Resolve(ctx, &target)
	require.NoError(t, err)
	defer localstore.CloseCredentials(cs)
	signer, err := cs[0].Signer()
	require.NoError(t, err)
	sig, err := signer.Sign(rand.Reader, []byte("fresh-device-proof"))
	require.NoError(t, err)
	require.NoError(t, public.Verify([]byte("fresh-device-proof"), sig))
	keyAfter, err := os.ReadFile(cfg.Servers["generated"].KeyPath)
	require.NoError(t, err)
	require.Equal(t, keyBefore, keyAfter)
	storeAfter, err := os.ReadFile(store.Path())
	require.NoError(t, err)
	require.Equal(t, storeBefore, storeAfter)
	require.NoFileExists(t, cfg.Servers["generated"].KeyPath+".passphrase")
}

func TestImportProtectedMetadataOnlyDoesNotOpenLockedStoreOrImportSecrets(t *testing.T) {
	cfg, store, _, _ := protectedImportFixture(t)
	cfg.Servers["password"] = &config.Server{Host: "password.invalid", User: "ops", Auth: config.AuthPassword}
	require.NoError(t, store.Put(context.Background(), cfg.Servers["password"], []localstore.Credential{{Password: []byte("synthetic-password")}}))
	require.NoError(t, store.Lock(context.Background()))
	data := NewData()
	report, err := data.ImportProtected(context.Background(), cfg, "synthetic-device", false, store, "")
	require.NoError(t, err)
	require.Empty(t, data.Credentials)
	require.Zero(t, report.Keys)
	require.Equal(t, 1, report.NeedsPasswords)
	for _, entry := range data.Entries {
		require.Empty(t, entry.CredentialIDs)
	}
}

func TestImportProtectedSavedAgentAndPasswordExactBindings(t *testing.T) {
	ctx := context.Background()
	cfg, store, c, public := protectedImportFixture(t)
	delete(cfg.Servers, "generated")
	agentTarget := &config.Server{Host: "agent.invalid", User: "ops", Auth: config.AuthAgent}
	passwordTarget := &config.Server{Host: "password.invalid", User: "ops", Auth: config.AuthPassword}
	cfg.Servers["saved-agent"] = agentTarget
	cfg.Servers["saved-password"] = passwordTarget
	require.NoError(t, store.Put(ctx, agentTarget, []localstore.Credential{c}))
	require.NoError(t, store.Put(ctx, passwordTarget, []localstore.Credential{{Password: []byte("synthetic-password")}}))
	data := NewData()
	defer data.Close()
	report, err := data.ImportProtected(ctx, cfg, "synthetic-device", true, store, "")
	require.NoError(t, err)
	require.Equal(t, 1, report.Keys)
	require.Zero(t, report.AgentOnly)
	require.Zero(t, report.NeedsPasswords)
	entry, err := data.Find("saved-agent")
	require.NoError(t, err)
	require.Equal(t, gssh.FingerprintSHA256(public), data.Credentials[entry.CredentialIDs[0]].Fingerprint)
	entry, err = data.Find("saved-password")
	require.NoError(t, err)
	require.Equal(t, "synthetic-password", data.Credentials[entry.CredentialIDs[0]].Password)
	changed := *agentTarget
	changed.User = "other"
	cfg.Servers = map[string]*config.Server{"saved-agent": &changed}
	unrelated := NewData()
	report, err = unrelated.ImportProtected(ctx, cfg, "synthetic-device", true, store, "")
	require.NoError(t, err)
	require.Empty(t, unrelated.Credentials)
	require.Equal(t, 1, report.AgentOnly)
}

func TestImportProtectedPreservesTombstoneConflictAndForeignBindings(t *testing.T) {
	cfg, store, _, _ := protectedImportFixture(t)
	ctx := context.Background()
	id := EntryID(cleanServer(*cfg.Servers["generated"]))
	deleted := NewData()
	deleted.Deleted[id] = true
	report, err := deleted.ImportProtected(ctx, cfg, "synthetic-device", true, store, "")
	require.NoError(t, err)
	require.Equal(t, 1, report.SkippedDeleted)
	require.Empty(t, deleted.Entries)
	require.Empty(t, deleted.Credentials)
	conflicted := NewData()
	_, err = conflicted.Import(cfg, "synthetic-device", false)
	require.NoError(t, err)
	entry := conflicted.Entries[id]
	conflicted.Conflicts[id] = Conflict{Local: &entry}
	_, err = conflicted.ImportProtected(ctx, cfg, "other-device", true, store, "")
	require.NoError(t, err)
	require.Equal(t, entry, conflicted.Entries[id])
	require.Contains(t, conflicted.Conflicts, id)
	require.Empty(t, conflicted.Credentials)
	foreign := *cfg.Servers["generated"]
	foreign.CloudEntry = id
	foreign.CloudVault = "foreign-owner"
	cfg.Servers = map[string]*config.Server{"generated": &foreign}
	data := NewData()
	_, err = data.ImportProtected(ctx, cfg, "synthetic-device", true, store, "")
	require.NoError(t, err)
	require.Empty(t, data.Entries)
	require.Empty(t, data.Credentials)
}

func TestImportProtectedRejectsLockedAndMismatchedProtectionWithoutFallback(t *testing.T) {
	cfg, store, _, _ := protectedImportFixture(t)
	ctx := context.Background()
	require.NoError(t, store.Lock(ctx))
	data := NewData()
	_, err := data.ImportProtected(ctx, cfg, "synthetic-device", true, store, "")
	require.Error(t, err)
	require.Empty(t, data.Credentials)
	require.NoError(t, store.Unlock(ctx))
	require.NoError(t, store.Update(ctx, func(d *localstore.Data) error {
		for id, c := range d.KeyFiles {
			c.Fingerprint = "SHA256:wrong"
			d.KeyFiles[id] = c
		}
		return nil
	}))
	_, err = data.ImportProtected(ctx, cfg, "synthetic-device", true, store, "")
	require.Error(t, err)
	require.Empty(t, data.Credentials)
}

func TestImportProtectedLegacyFallbackWithoutInitializedStore(t *testing.T) {
	cfg, _, _, _ := protectedImportFixture(t)
	legacy := NewData()
	defer legacy.Close()
	expected, err := legacy.Import(cfg, "synthetic-device", true)
	require.NoError(t, err)
	protected := NewData()
	defer protected.Close()
	store := localstore.New(filepath.Join(t.TempDir(), "uninitialized.toml"))
	actual, err := protected.ImportProtected(context.Background(), cfg, "synthetic-device", true, store, "")
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, legacy, protected)
}

func TestImportProtectedConflictingSavedPasswordsRequireSelection(t *testing.T) {
	_, store, _, _ := protectedImportFixture(t)
	target := &config.Server{Host: "password.invalid", User: "ops", Auth: config.AuthPassword}
	require.NoError(t, store.Put(context.Background(), target, []localstore.Credential{{Password: []byte("synthetic-a")}, {Password: []byte("synthetic-b")}}))
	cfg := config.New()
	cfg.Servers["password"] = target
	data := NewData()
	_, err := data.ImportProtected(context.Background(), cfg, "synthetic-device", true, store, "")
	require.ErrorContains(t, err, "local selection")
	require.Empty(t, data.Credentials)
	require.Empty(t, data.Entries)
}
