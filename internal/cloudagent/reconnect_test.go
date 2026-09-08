package cloudagent

import (
	"context"
	"github.com/coder/websocket"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRelayConflictRetriesWithoutStoppingAgent(t *testing.T) {
	v, _, e := cloudsync.NewVault("reconnect-test", []byte("test-unlock"))
	require.NoError(t, e)
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var attempts atomic.Int32
	connected := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) <= 2 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		ws, e := websocket.Accept(w, r, nil)
		if e != nil {
			return
		}
		defer ws.CloseNow()
		close(connected)
		_, _, _ = ws.Read(ctx)
	}))
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, &cloudsync.State{URL: server.URL, Username: "reconnect-test"}, v, 10*time.Millisecond)
	}()
	select {
	case e := <-done:
		t.Fatalf("relay conflict stopped agent: %v", e)
	case <-connected:
	case <-ctx.Done():
		t.Fatal("agent never reconnected")
	}
	require.Equal(t, int32(3), attempts.Load())
	cancel()
	require.NoError(t, <-done)
}

func TestRelayRevocationStillStopsAgent(t *testing.T) {
	v, _, e := cloudsync.NewVault("reconnect-test", []byte("test-unlock"))
	require.NoError(t, e)
	defer v.Close()
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { attempts.Add(1); w.WriteHeader(status) }))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			e := serve(ctx, &cloudsync.State{URL: server.URL, Username: "reconnect-test"}, v, 10*time.Millisecond)
			var api *cloudsync.APIError
			require.ErrorAs(t, e, &api)
			require.Equal(t, status, api.Status)
			require.Equal(t, int32(1), attempts.Load())
		})
	}
}
