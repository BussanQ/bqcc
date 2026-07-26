package web

import (
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/example/decentid/internal/app"
	qrcode "github.com/skip2/go-qrcode"
)

func (s *Server) apiSelfCheck(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	result, err := s.service.SelfCheck()
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "selfcheck_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiNotes(w http.ResponseWriter, r *http.Request) {
	if !s.requireGET(w, r) {
		return
	}
	overview, err := s.service.NotesOverview()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_notes_failed", err)
		return
	}
	s.writeOK(w, overview)
}

func (s *Server) apiConsolidateMemory(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	result, err := s.service.ConsolidateLegacyMemory()
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "consolidate_memory_failed", err)
		return
	}
	s.writeOK(w, result)
}

// apiQR renders a small data string (e.g. a DID identity code) as a PNG QR code.
func (s *Server) apiQR(w http.ResponseWriter, r *http.Request) {
	if !s.requireGET(w, r) {
		return
	}
	data := r.URL.Query().Get("data")
	if data == "" || len(data) > 512 {
		http.Error(w, "二维码内容为空或过长", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(data, qrcode.Medium, 320)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// apiBackupExport returns the passphrase-encrypted identity file as a download.
// Served from a plain HTML form so the browser handles the file download.
func (s *Server) apiBackupExport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "无法解析表单", http.StatusBadRequest)
		return
	}
	data, err := s.service.ExportBackup(r.FormValue("passphrase"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="decentid-backup.enc"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// apiBackupImport restores an encrypted backup uploaded via a multipart form,
// then redirects home on success.
func (s *Server) apiBackupImport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "无法解析上传文件", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		http.Error(w, "请选择备份文件", http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 8<<20))
	if err != nil {
		http.Error(w, "读取上传文件失败", http.StatusBadRequest)
		return
	}
	result, err := s.service.ImportBackup(data, r.FormValue("passphrase"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	query := url.Values{}
	query.Set("restored", result.Version)
	query.Set("objects", strconv.Itoa(result.RestoredObjectCount))
	if result.Scope == app.BackupScopeIdentityOnly {
		query.Set("warning", "这是旧版仅身份备份：已恢复钥匙串，但不包含内容目录、内容对象或他人背书；缺失的私有内容无法从网络恢复。")
	}
	http.Redirect(w, r, "/backup?"+query.Encode(), http.StatusSeeOther)
}
