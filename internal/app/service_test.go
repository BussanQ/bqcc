package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/internal/storage"
	"github.com/example/decentid/pkg/types"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	svc := NewService(filepath.Join(dir, "id.json"))
	if _, err := svc.CreateIdentity("Alice", "", false); err != nil {
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

func TestCreateIdentityRefusesOverwriteByDefault(t *testing.T) {
	svc := newTestService(t)
	before, err := svc.Summary()
	if err != nil {
		t.Fatalf("summary before: %v", err)
	}
	if _, err := svc.CreateIdentity("Bob", "", false); err == nil {
		t.Fatalf("expected existing identity to be protected")
	}
	after, err := svc.Summary()
	if err != nil {
		t.Fatalf("summary after: %v", err)
	}
	if after.DID != before.DID {
		t.Fatalf("identity changed after rejected overwrite")
	}
	if _, err := svc.CreateIdentity("Bob", "", true); err != nil {
		t.Fatalf("forced replace: %v", err)
	}
	replaced, err := svc.Summary()
	if err != nil {
		t.Fatalf("summary replaced: %v", err)
	}
	if replaced.DID == before.DID {
		t.Fatalf("forced replacement should create a new identity")
	}
}

func TestAddMemoryAccumulatesCurrentManifestAcrossRootRotation(t *testing.T) {
	svc := newTestService(t)
	before, err := svc.Summary()
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	first, err := svc.AddMemory("note", "one", types.VisibilityPublic)
	if err != nil {
		t.Fatalf("add first public memory: %v", err)
	}
	if _, err := svc.RotateRoot("new-root"); err != nil {
		t.Fatalf("rotate root: %v", err)
	}
	second, err := svc.AddMemory("note", "two", types.VisibilityPublic)
	if err != nil {
		t.Fatalf("add second public memory: %v", err)
	}
	if len(second.Manifest.Items) != 2 || second.Manifest.Items[0] != first.ObjectCID || second.Manifest.Items[1] != second.ObjectCID {
		t.Fatalf("unexpected accumulated public manifest: %#v", second.Manifest.Items)
	}
	if _, err := svc.AddMemory("note", "secret one", types.VisibilityPrivate); err != nil {
		t.Fatalf("add first private memory: %v", err)
	}
	privateSecond, err := svc.AddMemory("note", "secret two", types.VisibilityPrivate)
	if err != nil {
		t.Fatalf("add second private memory: %v", err)
	}
	if len(privateSecond.Manifest.Items) != 2 {
		t.Fatalf("expected two private manifest items, got %d", len(privateSecond.Manifest.Items))
	}

	notes, err := svc.ListNotes()
	if err != nil {
		t.Fatalf("list notes: %v", err)
	}
	if len(notes) != 4 {
		t.Fatalf("expected 4 current notes, got %d", len(notes))
	}
	for _, note := range notes {
		if note.Visibility == types.VisibilityPrivate && (!note.Locked || note.Preview != "") {
			t.Fatalf("private note should stay locked: %#v", note)
		}
	}
	after, err := svc.Summary()
	if err != nil {
		t.Fatalf("summary after: %v", err)
	}
	if after.DID != before.DID {
		t.Fatalf("DID changed after content updates and root rotation")
	}
	if _, err := svc.PublicState(); err != nil {
		t.Fatalf("public state should still replay: %v", err)
	}
}

func TestConsolidateLegacyMemoryFiltersOtherIdentities(t *testing.T) {
	svc := newTestService(t)
	id, err := storage.LoadIdentity(svc.IdentityPath())
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	rootPriv, err := id.PreferredRootPrivateKey()
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	legacy, err := memory.NewObject("note", "legacy", types.VisibilityPublic, nil, nil)
	if err != nil {
		t.Fatalf("new legacy object: %v", err)
	}
	if err := memory.SignObject(&legacy, rootPriv); err != nil {
		t.Fatalf("sign legacy object: %v", err)
	}
	if err := storage.WriteJSON(filepath.Join(filepath.Dir(svc.IdentityPath()), legacy.CID+".json"), legacy); err != nil {
		t.Fatalf("write legacy object: %v", err)
	}

	other, err := identity.New("Mallory")
	if err != nil {
		t.Fatalf("new other identity: %v", err)
	}
	otherPriv, err := other.PreferredRootPrivateKey()
	if err != nil {
		t.Fatalf("other root key: %v", err)
	}
	foreign, err := memory.NewObject("note", "foreign", types.VisibilityPublic, nil, nil)
	if err != nil {
		t.Fatalf("new foreign object: %v", err)
	}
	if err := memory.SignObject(&foreign, otherPriv); err != nil {
		t.Fatalf("sign foreign object: %v", err)
	}
	if err := storage.WriteJSON(filepath.Join(filepath.Dir(svc.IdentityPath()), foreign.CID+".json"), foreign); err != nil {
		t.Fatalf("write foreign object: %v", err)
	}

	status, err := svc.MemoryStatus()
	if err != nil {
		t.Fatalf("memory status: %v", err)
	}
	if status.LegacyPublic != 1 || status.LegacyPrivate != 0 {
		t.Fatalf("unexpected legacy status: %#v", status)
	}
	if _, err := svc.ExportBackup("pw-123"); err == nil {
		t.Fatalf("backup should require legacy content consolidation")
	}
	result, err := svc.ConsolidateLegacyMemory()
	if err != nil {
		t.Fatalf("consolidate legacy memory: %v", err)
	}
	if result.PublicAdded != 1 {
		t.Fatalf("expected one consolidated object, got %#v", result)
	}
	notes, err := svc.ListNotes()
	if err != nil {
		t.Fatalf("list consolidated notes: %v", err)
	}
	if len(notes) != 1 || notes[0].CID != legacy.CID {
		t.Fatalf("foreign object entered current manifest: %#v", notes)
	}
}

func TestBackupV2RestoresReferencedObjects(t *testing.T) {
	source := newTestService(t)
	if _, err := source.AddMemory("note", "hello", types.VisibilityPublic); err != nil {
		t.Fatalf("add public memory: %v", err)
	}
	privateMemory, err := source.AddMemory("note", "secret", types.VisibilityPrivate)
	if err != nil {
		t.Fatalf("add private memory: %v", err)
	}
	summary, err := source.Summary()
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	issued, err := source.IssueAttestation(summary.DID, "known", "Alice", "", time.Hour, "")
	if err != nil {
		t.Fatalf("issue attestation: %v", err)
	}
	attached, err := source.AttachAttestation(issued.Attestation)
	if err != nil {
		t.Fatalf("attach attestation: %v", err)
	}

	blob, err := source.ExportBackup("pw-123")
	if err != nil {
		t.Fatalf("export backup: %v", err)
	}
	if strings.Contains(string(blob), "secret") {
		t.Fatalf("encrypted backup leaked private plaintext")
	}

	destination := NewService(filepath.Join(t.TempDir(), "restored.json"))
	result, err := destination.ImportBackup(blob, "pw-123")
	if err != nil {
		t.Fatalf("import backup: %v", err)
	}
	if result.Version != "2" || result.Scope != BackupScopeComplete || result.RestoredObjectCount != 5 {
		t.Fatalf("unexpected import result: %#v", result)
	}
	selfCheck, err := destination.SelfCheck()
	if err != nil || !selfCheck.Valid {
		t.Fatalf("selfcheck after restore: result=%#v err=%v", selfCheck, err)
	}
	notes, err := destination.ListNotes()
	if err != nil {
		t.Fatalf("list restored notes: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("expected 2 restored notes, got %d", len(notes))
	}
	shown, err := destination.ShowMemory(filepath.Join(filepath.Dir(destination.IdentityPath()), privateMemory.ObjectCID+".json"))
	if err != nil {
		t.Fatalf("decrypt restored private memory: %v", err)
	}
	if shown.Plaintext != "secret" {
		t.Fatalf("unexpected restored plaintext %q", shown.Plaintext)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(destination.IdentityPath()), attached.CID+".json")); err != nil {
		t.Fatalf("restored attestation missing: %v", err)
	}
}

func TestBackupImportSupportsLegacyIdentityOnlyFile(t *testing.T) {
	source := newTestService(t)
	identityData, err := os.ReadFile(source.IdentityPath())
	if err != nil {
		t.Fatalf("read source identity: %v", err)
	}
	blob, err := icrypto.EncryptWithPassphrase(identityData, "pw-123")
	if err != nil {
		t.Fatalf("encrypt legacy backup: %v", err)
	}
	destination := NewService(filepath.Join(t.TempDir(), "restored.json"))
	result, err := destination.ImportBackup(blob, "pw-123")
	if err != nil {
		t.Fatalf("import legacy backup: %v", err)
	}
	if result.Scope != BackupScopeIdentityOnly || result.Version != "1" {
		t.Fatalf("legacy backup scope missing: %#v", result)
	}
	if _, err := destination.ImportBackup(blob, "wrong"); err == nil {
		t.Fatalf("expected wrong passphrase to fail")
	}
	if checked, err := destination.SelfCheck(); err != nil || !checked.Valid {
		t.Fatalf("legacy identity should remain usable: result=%#v err=%v", checked, err)
	}
}
