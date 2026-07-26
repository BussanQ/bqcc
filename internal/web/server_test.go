package web

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/decentid/internal/app"
	"github.com/example/decentid/pkg/types"
)

func newTestServer(t *testing.T) (*Server, *app.Service) {
	t.Helper()
	svc := app.NewService(filepath.Join(t.TempDir(), "identity.json"))
	if _, err := svc.CreateIdentity("Alice", "", false); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	server, err := New(svc)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server, svc
}

func performRequest(handler http.Handler, method, target string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.Host = "localhost"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestCreateAPIRefusesExistingIdentityAndSummaryHidesPrivateKeys(t *testing.T) {
	server, _ := newTestServer(t)
	handler := server.Handler()
	created := performRequest(handler, http.MethodPost, "/api/identity/create", bytes.NewBufferString(`{"displayName":"Bob"}`))
	if created.Code != http.StatusBadRequest {
		t.Fatalf("expected overwrite refusal, got %d: %s", created.Code, created.Body.String())
	}
	if !strings.Contains(created.Body.String(), "默认不会覆盖") {
		t.Fatalf("missing safe overwrite message: %s", created.Body.String())
	}

	summary := performRequest(handler, http.MethodGet, "/api/summary", nil)
	if summary.Code != http.StatusOK {
		t.Fatalf("summary status %d: %s", summary.Code, summary.Body.String())
	}
	body := summary.Body.String()
	if strings.Contains(body, "privateKey") || strings.Contains(body, "localKeys") {
		t.Fatalf("summary leaked private key fields: %s", body)
	}
	if summary.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("summary response should not be cached")
	}
}

func TestSimpleModeUsesAccurateSelfCheckAndDeviceCopy(t *testing.T) {
	server, _ := newTestServer(t)
	handler := server.Handler()
	prove := performRequest(handler, http.MethodGet, "/prove", nil)
	if prove.Code != http.StatusOK || !strings.Contains(prove.Body.String(), "本机签名自检") || !strings.Contains(prove.Body.String(), "不代表已经向第三方完成登录") {
		t.Fatalf("prove page copy is inaccurate: %s", prove.Body.String())
	}
	devices := performRequest(handler, http.MethodGet, "/devices", nil)
	if devices.Code != http.StatusOK || !strings.Contains(devices.Body.String(), "不是跨设备配对") {
		t.Fatalf("device page should explain local-only keys: %s", devices.Body.String())
	}
}

func TestNotesAPIReportsCurrentManifestStatus(t *testing.T) {
	server, svc := newTestServer(t)
	if _, err := svc.AddMemory("note", "hello", types.VisibilityPublic); err != nil {
		t.Fatalf("add memory: %v", err)
	}
	response := performRequest(server.Handler(), http.MethodGet, "/api/notes", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("notes status %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"linkedPublic": 1`) || !strings.Contains(body, `"legacyPublic": 0`) {
		t.Fatalf("notes status missing current manifest counts: %s", body)
	}
}
