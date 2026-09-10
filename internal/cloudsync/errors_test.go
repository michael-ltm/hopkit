package cloudsync

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestExplainsCloudErrors(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
		want   string
	}{
		{"invalid_login", 401, "account does not exist or password is incorrect"},
		{"unauthorized", 401, "sshm cloud login"},
		{"account_unavailable", 409, "username is unavailable"},
		{"invalid_recovery", 401, "recovery code"},
		{"rate_limited", 429, "try again later"},
		{"revision_conflict", 409, "sshm cloud sync"},
		{"device_limit", 409, "revoke"},
		{"device_relay_unavailable", 409, "offline"},
		{"future_error", 503, "try again later"},
		{"future_error", 418, "HTTP 418, future_error"},
	} {
		t.Run(tc.code+http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(`{"error":"` + tc.code + `"}`))
			}))
			defer srv.Close()
			s := State{URL: srv.URL}
			err := s.Request(context.Background(), "GET", "/v1/vault", nil, nil)
			var api *APIError
			if !errors.As(err, &api) || api.Code != tc.code || api.Status != tc.status {
				t.Fatalf("lost structured error: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q in %q", tc.want, err)
			}
		})
	}
}
