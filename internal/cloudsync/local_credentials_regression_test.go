//go:build !windows

package cloudsync

import (
	"context"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReviewNativeDeletionDisablesCredential(t *testing.T) {
	c, _, _ := loadTestCredential(t, "")
	s, v, cfg, path := loadTestVault(t, c)
	e := v.Data.Entries["entry-123"]
	delete(v.Data.Entries, "entry-123")
	e.ID = EntryID(cleanServer(e.Server))
	v.Data.Entries[e.ID] = e
	target := e.Server
	target.CloudVault = InventoryIdentity(s)
	cfg.Servers["local-alias"] = &target
	store := localstore.New(path)
	store.Protector = testutil.NewDeviceProtector()
	report, err := RememberVault(context.Background(), s, v, cfg, store)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	v.Data.Deleted[e.ID] = true
	_, err = RememberVault(context.Background(), s, v, cfg, store)
	require.NoError(t, err)
	cs, err := store.Resolve(context.Background(), &target)
	localstore.CloseCredentials(cs)
	require.ErrorIs(t, err, localstore.ErrInactive)
}
func TestReviewInventoryRetainsLocalRoute(t *testing.T) {
	c, _, _ := loadTestCredential(t, "")
	s, v, cfg, path := loadTestVault(t, c)
	cfg.Servers["local-alias"].Proxy = "socks5://127.0.0.1:1080"
	require.NoError(t, config.Save(path, cfg))
	_, err := PublishInventory(path, s, v.Data)
	require.NoError(t, err)
	got, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, "socks5://127.0.0.1:1080", got.Servers["local-alias"].Proxy)
}

func TestRotatedVaultRebindsOnlyAssociatedTargets(t *testing.T) {
	c, _, _ := loadTestCredential(t, "")
	s, v, cfg, path := loadTestVault(t, c)
	oldOwner := InventoryIdentity(s)
	cfg.Servers["local-alias"].Proxy = "socks5://127.0.0.1:1080"
	other := *cfg.Servers["local-alias"]
	other.CloudVault = "unrelated-vault"
	cfg.Servers["other"] = &other
	require.NoError(t, config.Save(path, cfg))
	v.Master[0]++
	s.Base.RootPublic = v.Public()
	require.NoError(t, RebindRotatedInventory(path, s, v, oldOwner))
	updated, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, InventoryIdentity(s), updated.Servers["local-alias"].CloudVault)
	require.Equal(t, "socks5://127.0.0.1:1080", updated.Servers["local-alias"].Proxy)
	require.Equal(t, "unrelated-vault", updated.Servers["other"].CloudVault)
}

func TestReviewConflictRetainsUsableCloudMarker(t *testing.T) {
	c, _, _ := loadTestCredential(t, "")
	s, v, cfg, path := loadTestVault(t, c)
	require.NoError(t, config.Save(path, cfg))
	store := localstore.New(path)
	store.Protector = testutil.NewDeviceProtector()
	_, err := RememberVault(context.Background(), s, v, cfg, store)
	require.NoError(t, err)
	entry := v.Data.Entries["entry-123"]
	v.Data.Conflicts[entry.ID] = Conflict{Local: &entry, Remote: &entry}
	_, err = RememberVault(context.Background(), s, v, cfg, store)
	require.NoError(t, err)
	_, err = PublishInventory(path, s, v.Data)
	require.NoError(t, err)
	got, err := config.Load(path)
	require.NoError(t, err)
	require.NotNil(t, got.Servers["local-alias"], "last verified local connection must remain addressable while sync conflicts")
	cs, err := store.Resolve(context.Background(), got.Servers["local-alias"])
	require.NoError(t, err)
	defer localstore.CloseCredentials(cs)
	_, err = cs[0].Signer()
	require.NoError(t, err)
}
