package cloudsync

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstalledVersionRejectsUnknownFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown")
	if err := os.WriteFile(path, []byte("not an SSHM executable"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := installedVersionAt(context.Background(), path); err == nil {
		t.Fatal("accepted unidentified executable")
	}
	var out boundedVersionOutput
	if _, err := out.Write(make([]byte, 129)); err == nil {
		t.Fatal("unbounded version output")
	}
}

// Run against two real release executables. The test process never changes;
// after replacement the observation must follow disk, including a downgrade.
func TestInstalledVersionReplacementIntegration(t *testing.T) {
	old, new := os.Getenv("SSHM_VERSION_TEST_OLD"), os.Getenv("SSHM_VERSION_TEST_NEW")
	if old == "" || new == "" {
		t.Skip("set both real release binary paths")
	}
	name := "sshm"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	for _, tc := range []struct{ src, want string }{{old, "0.8.0-cloud-preview.29"}, {new, "0.8.0-cloud-preview.30"}, {old, "0.8.0-cloud-preview.29"}} {
		data, err := os.ReadFile(tc.src)
		if err != nil {
			t.Fatal(err)
		}
		stage := path + ".stage"
		if err = os.WriteFile(stage, data, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(path)
		if err = os.Rename(stage, path); err != nil {
			t.Fatal(err)
		}
		got, err := installedVersionAt(context.Background(), path)
		if err != nil || got != tc.want {
			t.Fatalf("installed=%q want=%q error=%v", got, tc.want, err)
		}
	}
}
