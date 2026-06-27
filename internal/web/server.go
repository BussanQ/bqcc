package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/example/decentid/internal/app"
)

type Server struct {
	service   *app.Service
	templates *template.Template
	static    fs.FS
}

type Option struct {
	Service *app.Service
}

func New(service *app.Service) (*Server, error) {
	if service == nil {
		return nil, errors.New("service is required")
	}
	staticFS, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("layout.html").Funcs(template.FuncMap{
		"json":        toPrettyJSON,
		"short":       shortValue,
		"pageTitle":   pageTitle,
		"activeClass": activeClass,
	}).ParseFS(embeddedFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{service: service, templates: tmpl, static: staticFS}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(s.static))))

	// Simple mode (default, consumer-facing) at the root.
	mux.HandleFunc("/", s.page("/", "simple_home.html", "home", "我的身份"))
	mux.HandleFunc("/prove", s.page("/prove", "simple_prove.html", "prove", "证明我是我"))
	mux.HandleFunc("/notes", s.page("/notes", "simple_notes.html", "notes", "我的内容"))
	mux.HandleFunc("/devices", s.page("/devices", "simple_devices.html", "devices", "我的设备"))
	mux.HandleFunc("/backup", s.page("/backup", "simple_backup.html", "backup", "备份与恢复"))

	// Advanced mode (protocol console) under /advanced.
	mux.HandleFunc("/advanced", s.page("/advanced", "dashboard.html", "dashboard", "控制台"))
	mux.HandleFunc("/advanced/identity", s.page("/advanced/identity", "identity.html", "identity", "身份"))
	mux.HandleFunc("/advanced/memory", s.page("/advanced/memory", "memory.html", "memory", "记忆"))
	mux.HandleFunc("/advanced/devices", s.page("/advanced/devices", "devices.html", "devices", "设备"))
	mux.HandleFunc("/advanced/auth", s.page("/advanced/auth", "auth.html", "auth", "认证"))
	mux.HandleFunc("/advanced/attestations", s.page("/advanced/attestations", "attestations.html", "attestations", "证明"))
	mux.HandleFunc("/advanced/network", s.page("/advanced/network", "network.html", "network", "网络"))

	mux.HandleFunc("/api/summary", s.apiSummary)
	mux.HandleFunc("/api/selfcheck", s.apiSelfCheck)
	mux.HandleFunc("/api/notes", s.apiNotes)
	mux.HandleFunc("/api/qr", s.apiQR)
	mux.HandleFunc("/api/backup/export", s.apiBackupExport)
	mux.HandleFunc("/api/backup/import", s.apiBackupImport)
	mux.HandleFunc("/api/identity/create", s.apiCreateIdentity)
	mux.HandleFunc("/api/identity/public-state", s.apiPublicState)
	mux.HandleFunc("/api/identity/export-state", s.apiExportState)
	mux.HandleFunc("/api/memory/add", s.apiAddMemory)
	mux.HandleFunc("/api/memory/show", s.apiShowMemory)
	mux.HandleFunc("/api/devices/add", s.apiAddDevice)
	mux.HandleFunc("/api/devices/revoke", s.apiRevokeDevice)
	mux.HandleFunc("/api/devices/rotate-root", s.apiRotateRoot)
	mux.HandleFunc("/api/auth/challenge", s.apiCreateChallenge)
	mux.HandleFunc("/api/auth/respond", s.apiRespondChallenge)
	mux.HandleFunc("/api/auth/verify", s.apiVerifyChallenge)
	mux.HandleFunc("/api/attestations/issue", s.apiIssueAttestation)
	mux.HandleFunc("/api/attestations/verify", s.apiVerifyAttestation)
	mux.HandleFunc("/api/attestations/attach", s.apiAttachAttestation)
	mux.HandleFunc("/api/network/publish", s.apiPublish)
	mux.HandleFunc("/api/network/resolve", s.apiResolve)
	return s.security(mux)
}

func (s *Server) ListenAndServe(addr string) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func (s *Server) page(path, templateName, active, title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			s.methodNotAllowed(w)
			return
		}
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		summary, err := s.service.Summary()
		if err != nil {
			summary = app.LocalSummary{HasIdentity: false, IdentityPath: s.service.IdentityPath(), Warning: err.Error()}
		}
		data := PageData{Title: title, Active: active, Summary: summary, IdentityPath: s.service.IdentityPath(), Now: time.Now().UTC()}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.templates.ExecuteTemplate(w, templateName, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (s *Server) renderPartial(name string, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, out interface{}) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("请求体必须只包含一个 JSON 对象")
	}
	return nil
}

func (s *Server) writeOK(w http.ResponseWriter, data interface{}) {
	s.writeJSON(w, http.StatusOK, APIResponse{OK: true, Data: data})
}

func (s *Server) writeError(w http.ResponseWriter, status int, code string, err error) {
	message := code
	if err != nil {
		message = err.Error()
	}
	s.writeJSON(w, status, APIResponse{OK: false, Error: &APIError{Code: code, Message: message}})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func (s *Server) requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return false
	}
	return true
}

func (s *Server) requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w)
		return false
	}
	return true
}

func (s *Server) methodNotAllowed(w http.ResponseWriter) {
	s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("不支持的请求方法"))
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalHost(r.Host) {
			http.Error(w, "DecentID Web 操作台默认只接受 localhost Host", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/advanced/") || r.URL.Path == "/notes" || r.URL.Path == "/backup" {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func isLocalHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func toPrettyJSON(value interface{}) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
}

func shortValue(value string) string {
	if len(value) <= 18 {
		return value
	}
	return value[:10] + "…" + value[len(value)-6:]
}

func pageTitle(title string) string {
	if title == "" {
		return "DecentID 操作台"
	}
	return title + " · DecentID 操作台"
}

func activeClass(current, active string) string {
	if current == active {
		return "is-active"
	}
	return ""
}
