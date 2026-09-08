package cloudsync

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func signedJob(v *Vault) Job {
	j := Job{ID: RandomID(), Device: "device_test", Action: "sync", Expires: time.Now().Add(time.Hour).UnixMilli(), Status: "queued"}
	j.Signature = encoding.EncodeToString(ed25519.Sign(v.private(), []byte(j.Message("test-account"))))
	return j
}
func TestJobSignatureBindsActionDeviceAccountAndExpiry(t *testing.T) {
	v, _ := fixture(t)
	j := signedJob(v)
	require.True(t, v.VerifyJob(j, "test-account", j.Device))
	require.False(t, v.VerifyJob(j, "other-account", j.Device))
	require.False(t, v.VerifyJob(j, "test-account", "other_device"))
	for _, edit := range []func(*Job){func(j *Job) { j.Action = "update" }, func(j *Job) { j.Version = "changed" }, func(j *Job) { j.ID = RandomID() }, func(j *Job) { j.Expires = time.Now().Add(-time.Minute).UnixMilli() }} {
		bad := j
		edit(&bad)
		require.False(t, v.VerifyJob(bad, "test-account", bad.Device))
	}
}
func TestJobLostReceiptDoesNotRepeatAction(t *testing.T) {
	v, _ := fixture(t)
	j := signedJob(v)
	var reports atomic.Int32
	var running atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/jobs/poll":
			out := j
			if running.Load() {
				out.Status = "running"
			}
			json.NewEncoder(w).Encode(map[string]any{"jobs": []Job{out}})
		case "/v1/jobs/" + j.ID + "/claim":
			running.Store(true)
			w.Write([]byte(`{}`))
		case "/v1/jobs/" + j.ID + "/result":
			var result JobResult
			json.NewDecoder(r.Body).Decode(&result)
			pub, _ := encoding.DecodeString(v.Public())
			sig, _ := encoding.DecodeString(result.Receipt)
			if !ed25519.Verify(pub, []byte(result.Message("test-account", j)), sig) {
				w.WriteHeader(403)
				return
			}
			if reports.Add(1) == 1 {
				w.WriteHeader(503)
				w.Write([]byte(`{"error":"unavailable"}`))
				return
			}
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s := &State{URL: server.URL, Username: "test-account", DeviceID: j.Device}
	path := filepath.Join(t.TempDir(), "state.json")
	count := 0
	execute := func(context.Context, Job) JobResult {
		count++
		return JobResult{Status: "succeeded", Code: "synced", Count: 2}
	}
	require.Error(t, s.ProcessJobs(context.Background(), v, path, execute))
	require.NoError(t, s.ProcessJobs(context.Background(), v, path, execute))
	require.Equal(t, 1, count)
	require.Equal(t, int32(2), reports.Load())
}
func TestJobInterruptedExecutionIsNotRetried(t *testing.T) {
	v, _ := fixture(t)
	j := signedJob(v)
	claim := RandomID()
	path := filepath.Join(t.TempDir(), "state.json")
	journal := map[string]jobRecord{Digest([]string{"test-account", j.Device, j.Signature}): {Result: JobResult{Claim: claim, Status: "failed", Code: "interrupted"}, Expires: j.Expires}}
	b, _ := json.Marshal(journal)
	require.NoError(t, WritePrivate(path+".jobs.json", b))
	var result JobResult
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/jobs/poll" {
			json.NewEncoder(w).Encode(map[string]any{"jobs": []Job{j}})
			return
		}
		if r.URL.Path == "/v1/jobs/"+j.ID+"/result" {
			json.NewDecoder(r.Body).Decode(&result)
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	s := &State{URL: server.URL, Username: "test-account", DeviceID: j.Device}
	require.NoError(t, s.ProcessJobs(context.Background(), v, path, func(context.Context, Job) JobResult {
		t.Fatal("must not repeat interrupted action")
		return JobResult{}
	}))
	require.Equal(t, "interrupted", result.Code)
}
