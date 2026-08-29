package pair

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandler_AcceptsIdenticalRetryButRejectsChangedReport(t *testing.T) {
	reports := make(chan Report, 1)
	retries := make(chan struct{}, 1)
	handler := HandlerWithRetrySignal("secret", reports, retries)
	body, err := json.Marshal(Report{User: " Administrator ", Hostname: "WINDOWS-HOST", Platform: "Windows"})
	require.NoError(t, err)
	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, CallbackPath("secret"), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request())
	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.Equal(t, Report{User: "Administrator", Hostname: "WINDOWS-HOST", Platform: "windows"}, <-reports)

	duplicate := httptest.NewRecorder()
	handler.ServeHTTP(duplicate, request())
	require.Equal(t, http.StatusAccepted, duplicate.Code)
	select {
	case <-retries:
	default:
		t.Fatal("identical retry did not signal that its response was served")
	}
	select {
	case duplicateReport := <-reports:
		t.Fatalf("duplicate callback was enqueued again: %#v", duplicateReport)
	default:
	}

	changed := httptest.NewRecorder()
	changedReq := httptest.NewRequest(http.MethodPost, CallbackPath("secret"), strings.NewReader(`{"user":"Other","hostname":"WINDOWS-HOST","platform":"windows"}`))
	changedReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(changed, changedReq)
	require.Equal(t, http.StatusConflict, changed.Code)
}

func TestHandler_AcceptsFormReport(t *testing.T) {
	reports := make(chan Report, 1)
	form := url.Values{"user": {"ubuntu"}, "hostname": {"web-1"}, "platform": {"linux"}}
	req := httptest.NewRequest(http.MethodPost, CallbackPath("token"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	Handler("token", reports).ServeHTTP(recorder, req)
	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.Equal(t, "ubuntu", (<-reports).User)
}

func TestHandler_RejectsWrongPathAndControlCharacters(t *testing.T) {
	reports := make(chan Report, 1)
	handler := Handler("right", reports)

	wrong := httptest.NewRecorder()
	handler.ServeHTTP(wrong, httptest.NewRequest(http.MethodPost, CallbackPath("wrong"), strings.NewReader(`{}`)))
	require.Equal(t, http.StatusNotFound, wrong.Code)

	invalid := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, CallbackPath("right"), strings.NewReader(`{"user":"bad\nuser","hostname":"h","platform":"linux"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(invalid, req)
	require.Equal(t, http.StatusBadRequest, invalid.Code)
}

func TestCallbackURL_IPv6AndRedaction(t *testing.T) {
	raw := CallbackURL("fd7a:115c:a1e0::1", 4567, "secret")
	require.Equal(t, "http://[fd7a:115c:a1e0::1]:4567/v1/pair/secret", raw)
	require.Equal(t, "http://[fd7a:115c:a1e0::1]:4567/v1/pair/%3Credacted%3E", RedactedURL(raw))
}

func TestValidateCallbackHost_OnlyAllowsPrivateOrHostname(t *testing.T) {
	require.NoError(t, ValidateCallbackHost("100.64.0.1"))
	require.NoError(t, ValidateCallbackHost("192.168.1.5"))
	require.NoError(t, ValidateCallbackHost("fd7a:115c:a1e0::1"))
	require.Error(t, ValidateCallbackHost("[fe80::1]"), "IPv6 link-local without a zone is not portable")
	require.Error(t, ValidateCallbackHost("fe80::1%en0"), "a zone-qualified link-local address must fail closed until zones are preserved end to end")
	require.NoError(t, ValidateCallbackHost("node.tailnet.test"))
	require.NoError(t, ValidateCallbackHost("att-dev."))
	require.Error(t, ValidateCallbackHost("8.8.8.8"))
	require.Error(t, ValidateCallbackHost("8.8.8.8."), "a trailing dot must not bypass public-IP classification")
	require.Error(t, ValidateCallbackHost("134744072"), "a legacy numeric hostname must not bypass public-IP classification")
	require.Error(t, ValidateCallbackHost("0x08080808"), "a hexadecimal numeric hostname must not bypass public-IP classification")
	require.Error(t, ValidateCallbackHost("010.010.010.010"), "an octal numeric hostname must not bypass public-IP classification")
	require.Error(t, ValidateCallbackHost("2001:4860:4860::8888"))
	require.Error(t, ValidateCallbackHost("198.18.0.1"), "common TUN fake-IP range must not become a callback address")
	require.Error(t, ValidateCallbackHost("host:8080"))
	require.Error(t, ValidateCallbackHost("x@8.8.8.8"))
	require.Error(t, ValidateCallbackHost("bad host"))
	require.Error(t, ValidateCallbackHost("-bad.local"))
	require.Error(t, ValidateCallbackHost("bad_.local"))
}

func TestTrustedCallbackIPRejectsPublicAndTUNFakeRanges(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.2", "100.64.0.1", "fd7a:115c:a1e0::1"} {
		require.True(t, trustedCallbackIP(netip.MustParseAddr(value)), value)
	}
	for _, value := range []string{"8.8.8.8", "198.18.0.1", "2001:4860:4860::8888", "fe80::1%en0"} {
		require.False(t, trustedCallbackIP(netip.MustParseAddr(value)), value)
	}
}
