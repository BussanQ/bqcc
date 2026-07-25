package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/decentid/pkg/types"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	svc := NewService(filepath.Join(dir, "id.json"))
	if _, err := svc.CreateIdentity("Alice", ""); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	return svc
}

func TestSelfCheck(t *testing.T) {
	svc := newTestService(t)
	result, err := svc.SelfCheck()
	if err != nil {
		t.Fatalf("selfcheck: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected selfcheck to pass: %s", result.Message)
	}
}

func TestListNotesScansObjects(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.AddMemory("note", "hello", types.VisibilityPublic); err != nil {
		t.Fatalf("add public memory: %v", err)
	}
	if _, err := svc.AddMemory("note", "secret", types.VisibilityPrivate); err != nil {
		t.Fatalf("add private memory: %v", err)
	}
	notes, err := svc.ListNotes()
	if err != nil {
		t.Fatalf("list notes: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("expected 2 notes, got %d", len(notes))
	}
	var publicSeen, privateSeen bool
	for _, n := range notes {
		if n.Visibility == types.VisibilityPrivate {
			privateSeen = true
			if !n.Locked || n.Preview != "" {
				t.Fatalf("private note should be locked with no preview")
			}
		} else {
			publicSeen = true
			if n.Locked || n.Preview != "hello" {
				t.Fatalf("public note should show preview, got locked=%v preview=%q", n.Locked, n.Preview)
			}
		}
	}
	if !publicSeen || !privateSeen {
		t.Fatalf("expected both a public and a private note")
	}
}

func TestBackupExportImportRoundTrip(t *testing.T) {
	svc := newTestService(t)

	blob, err := svc.ExportBackup("pw-123")
	if err != nil {
		t.Fatalf("export backup: %v", err)
	}

	// Corrupt the on-disk identity, then restore from the backup.
	if err := os.WriteFile(svc.IdentityPath(), []byte("{}"), 0o600); err != nil {
		t.Fatalf("corrupt identity: %v", err)
	}
	if err := svc.ImportBackup(blob, "wrong"); err == nil {
		t.Fatalf("expected wrong passphrase to fail")
	}
	if err := svc.ImportBackup(blob, "pw-123"); err != nil {
		t.Fatalf("import backup: %v", err)
	}

	result, err := svc.SelfCheck()
	if err != nil {
		t.Fatalf("selfcheck after restore: %v", err)
	}
	if !result.Valid {
		t.Fatalf("identity should be valid after restore")
	}
}
