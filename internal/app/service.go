package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/decentid/internal/attestation"
	"github.com/example/decentid/internal/auth"
	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/internal/p2p"
	"github.com/example/decentid/internal/storage"
	"github.com/example/decentid/pkg/types"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	DefaultIdentityPath = "identity.json"
	DefaultP2PListen    = "/ip4/127.0.0.1/tcp/0"
)

type Service struct {
	mu              sync.Mutex
	identityPath    string
	publishCancel   context.CancelFunc
	publishResolver *p2p.Resolver
}

type KeyCounts struct {
	Root       int `json:"root"`
	Device     int `json:"device"`
	Encryption int `json:"encryption"`
	Revoked    int `json:"revoked"`
}

type KeySummary struct {
	ID                    string        `json:"id"`
	Type                  string        `json:"type"`
	Role                  types.KeyRole `json:"role"`
	PublicKey             string        `json:"publicKey"`
	AddedAt               time.Time     `json:"addedAt"`
	RevokedAt             time.Time     `json:"revokedAt,omitempty"`
	RevokedReason         string        `json:"revokedReason,omitempty"`
	PreferredRoot         bool          `json:"preferredRoot"`
	PreferredDevice       bool          `json:"preferredDevice"`
	PreferredEncryption   bool          `json:"preferredEncryption"`
	HasLocalPrivateKey    bool          `json:"hasLocalPrivateKey"`
	LocalPrivateKeyLabel  string        `json:"localPrivateKeyLabel,omitempty"`
	LocalPrivateKeyHidden bool          `json:"localPrivateKeyHidden"`
}

type LocalSummary struct {
	HasIdentity              bool         `json:"hasIdentity"`
	IdentityPath             string       `json:"identityPath"`
	DID                      string       `json:"did,omitempty"`
	Version                  string       `json:"version,omitempty"`
	DisplayName              string       `json:"displayName,omitempty"`
	RootKeyID                string       `json:"rootKeyId,omitempty"`
	PreferredRootKeyID       string       `json:"preferredRootKeyId,omitempty"`
	PreferredDeviceKeyID     string       `json:"preferredDeviceKeyId,omitempty"`
	PreferredEncryptionKeyID string       `json:"preferredEncryptionKeyId,omitempty"`
	PublicMemoryRoot         string       `json:"publicMemoryRoot,omitempty"`
	PrivateMemoryRoot        string       `json:"privateMemoryRoot,omitempty"`
	LatestEventID            string       `json:"latestEventId,omitempty"`
	EventCount               int          `json:"eventCount"`
	AttestationCount         int          `json:"attestationCount"`
	KeyCounts                KeyCounts    `json:"keyCounts"`
	Keys                     []KeySummary `json:"keys,omitempty"`
	Warning                  string       `json:"warning,omitempty"`
}

type CreateIdentityResult struct {
	Summary LocalSummary              `json:"summary"`
	State   types.SignedIdentityState `json:"publicState"`
}

type PublicStateResult struct {
	State types.SignedIdentityState `json:"state"`
}

type ExportStateResult struct {
	OutFile string                    `json:"outFile"`
	State   types.SignedIdentityState `json:"state"`
}

type MemoryResult struct {
	ObjectCID    string               `json:"objectCid"`
	ManifestCID  string               `json:"manifestCid"`
	ObjectFile   string               `json:"objectFile"`
	ManifestFile string               `json:"manifestFile"`
	Visibility   types.Visibility     `json:"visibility"`
	Object       types.MemoryObject   `json:"object"`
	Manifest     types.MemoryManifest `json:"manifest"`
}

type ShowMemoryResult struct {
	MemoryFile string             `json:"memoryFile"`
	Visibility types.Visibility   `json:"visibility"`
	Object     types.MemoryObject `json:"object"`
	Plaintext  string             `json:"plaintext,omitempty"`
	Revealed   bool               `json:"revealed"`
}

type VerificationResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

type ChallengeResult struct {
	Challenge types.Challenge `json:"challenge"`
}

type ChallengeResponseResult struct {
	Response types.ChallengeResponse `json:"response"`
}

type AttestationResult struct {
	Attestation types.Attestation `json:"attestation"`
	OutFile     string            `json:"outFile,omitempty"`
}

type AttachAttestationResult struct {
	CID  string `json:"cid"`
	File string `json:"file"`
}

type PublishResult struct {
	Addresses            []string  `json:"addresses"`
	IdentityID           string    `json:"identityId"`
	StoredObjectCIDs     []string  `json:"storedObjectCids"`
	IncludeAttestations  bool      `json:"includeAttestations"`
	PrivateMemoryOmitted bool      `json:"privateMemoryOmitted"`
	ExpiresAt            time.Time `json:"expiresAt"`
}

type ResolveResult struct {
	State types.SignedIdentityState `json:"state"`
}

type BackupScope string

const (
	BackupScopeComplete     BackupScope = "complete"
	BackupScopeIdentityOnly BackupScope = "identity-only"
)

type BackupImportResult struct {
	Version             string      `json:"version"`
	Scope               BackupScope `json:"scope"`
	RestoredObjectCount int         `json:"restoredObjectCount"`
}

func NewService(identityPath string) *Service {
	if strings.TrimSpace(identityPath) == "" {
		identityPath = DefaultIdentityPath
	}
	return &Service{identityPath: identityPath}
}

func (s *Service) IdentityPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identityPath
}

func (s *Service) setIdentityPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identityPath = path
}

func (s *Service) Summary() (LocalSummary, error) {
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LocalSummary{HasIdentity: false, IdentityPath: path, Warning: "本地 identity 文件尚不存在；请先创建身份。"}, nil
		}
		return LocalSummary{HasIdentity: false, IdentityPath: path}, err
	}
	return buildSummary(path, id), nil
}

func (s *Service) CreateIdentity(displayName, outPath string, overwrite bool) (CreateIdentityResult, error) {
	if strings.TrimSpace(outPath) == "" {
		outPath = s.IdentityPath()
	}
	if strings.TrimSpace(outPath) == "" {
		return CreateIdentityResult{}, errors.New("需要提供身份输出路径")
	}
	if _, err := os.Stat(outPath); err == nil && !overwrite {
		return CreateIdentityResult{}, fmt.Errorf("身份文件 %s 已存在；为保护本地钥匙串，默认不会覆盖", outPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return CreateIdentityResult{}, err
	}
	id, err := identity.New(displayName)
	if err != nil {
		return CreateIdentityResult{}, err
	}
	if err := storage.SaveIdentity(outPath, id); err != nil {
		return CreateIdentityResult{}, err
	}
	s.setIdentityPath(outPath)
	return CreateIdentityResult{Summary: buildSummary(outPath, id), State: id.SignedState()}, nil
}

func (s *Service) PublicState() (PublicStateResult, error) {
	id, _, err := s.loadIdentityWithPath()
	if err != nil {
		return PublicStateResult{}, err
	}
	state := id.SignedState()
	if err := identity.VerifyState(state); err != nil {
		return PublicStateResult{}, err
	}
	return PublicStateResult{State: state}, nil
}

func (s *Service) ExportState(outPath string) (ExportStateResult, error) {
	id, identityPath, err := s.loadIdentityWithPath()
	if err != nil {
		return ExportStateResult{}, err
	}
	if strings.TrimSpace(outPath) == "" {
		outPath = filepath.Join(filepath.Dir(identityPath), "identity-state.json")
	}
	state := id.SignedState()
	if err := identity.VerifyState(state); err != nil {
		return ExportStateResult{}, err
	}
	if err := storage.WriteJSON(outPath, state); err != nil {
		return ExportStateResult{}, err
	}
	return ExportStateResult{OutFile: outPath, State: state}, nil
}

func (s *Service) AddMemory(kind, payload string, visibility types.Visibility) (MemoryResult, error) {
	if strings.TrimSpace(kind) == "" {
		kind = "note"
	}
	if visibility == "" {
		visibility = types.VisibilityPublic
	}
	if visibility != types.VisibilityPublic && visibility != types.VisibilityPrivate {
		return MemoryResult{}, fmt.Errorf("当前操作界面暂不支持可见性 %q", visibility)
	}
	id, identityPath, err := s.loadIdentityWithPath()
	if err != nil {
		return MemoryResult{}, err
	}
	rootPriv, err := id.PreferredRootPrivateKey()
	if err != nil {
		return MemoryResult{}, err
	}
	existing, err := storage.LoadCurrentMemoryObjects(identityPath, id.SignedState(), visibility)
	if err != nil {
		return MemoryResult{}, err
	}

	var obj types.MemoryObject
	if visibility == types.VisibilityPrivate {
		encryptionKeyID := id.EncryptionKeyID()
		if encryptionKeyID == "" {
			return MemoryResult{}, errors.New("没有可用的 active encryption key")
		}
		publicKey, err := identity.ResolveEncryptionPublicKey(id.Document, encryptionKeyID)
		if err != nil {
			return MemoryResult{}, err
		}
		obj, err = memory.NewPrivateObject(kind, payload, encryptionKeyID, publicKey, nil, nil)
		if err != nil {
			return MemoryResult{}, err
		}
	} else {
		obj, err = memory.NewObject(kind, payload, visibility, nil, nil)
		if err != nil {
			return MemoryResult{}, err
		}
	}
	if err := memory.SignObject(&obj, rootPriv); err != nil {
		return MemoryResult{}, err
	}
	items := append(existing, obj)
	manifest, err := memory.NewManifest(visibility, items)
	if err != nil {
		return MemoryResult{}, err
	}
	if err := memory.SignManifest(&manifest, rootPriv); err != nil {
		return MemoryResult{}, err
	}

	baseDir := filepath.Dir(identityPath)
	objectFile := filepath.Join(baseDir, obj.CID+".json")
	manifestFile := filepath.Join(baseDir, manifest.CID+".json")
	if err := storage.WriteJSON(objectFile, obj); err != nil {
		return MemoryResult{}, err
	}
	if err := storage.WriteJSON(manifestFile, manifest); err != nil {
		return MemoryResult{}, err
	}
	if visibility == types.VisibilityPrivate {
		if err := id.AddPrivateMemoryRoot(manifest.CID); err != nil {
			return MemoryResult{}, err
		}
	} else if err := id.AddPublicMemoryRoot(manifest.CID); err != nil {
		return MemoryResult{}, err
	}
	if err := storage.SaveIdentity(identityPath, id); err != nil {
		return MemoryResult{}, err
	}
	return MemoryResult{ObjectCID: obj.CID, ManifestCID: manifest.CID, ObjectFile: objectFile, ManifestFile: manifestFile, Visibility: visibility, Object: obj, Manifest: manifest}, nil
}

func (s *Service) ShowMemory(memoryFile string) (ShowMemoryResult, error) {
	if strings.TrimSpace(memoryFile) == "" {
		return ShowMemoryResult{}, errors.New("需要提供记忆对象文件路径")
	}
	id, _, err := s.loadIdentityWithPath()
	if err != nil {
		return ShowMemoryResult{}, err
	}
	var obj types.MemoryObject
	if err := storage.ReadJSON(memoryFile, &obj); err != nil {
		return ShowMemoryResult{}, err
	}
	result := ShowMemoryResult{MemoryFile: memoryFile, Visibility: obj.Visibility, Object: obj}
	if obj.Visibility != types.VisibilityPrivate {
		result.Plaintext = obj.Payload
		result.Revealed = true
		return result, nil
	}
	priv, err := id.PreferredEncryptionPrivateKey()
	if err != nil {
		return ShowMemoryResult{}, err
	}
	plaintext, err := memory.DecryptObject(obj, priv)
	if err != nil {
		return ShowMemoryResult{}, err
	}
	result.Plaintext = plaintext
	result.Revealed = true
	return result, nil
}

// NoteSummary is a friendly, listable view of a memory object for the simple UI.
type NoteSummary struct {
	CID        string           `json:"cid"`
	Type       string           `json:"type"`
	CreatedAt  time.Time        `json:"createdAt"`
	Visibility types.Visibility `json:"visibility"`
	Preview    string           `json:"preview,omitempty"`
	Locked     bool             `json:"locked"`
	File       string           `json:"file"`
}

type MemoryStatus struct {
	LinkedPublic  int `json:"linkedPublic"`
	LinkedPrivate int `json:"linkedPrivate"`
	LegacyPublic  int `json:"legacyPublic"`
	LegacyPrivate int `json:"legacyPrivate"`
}

type NotesOverview struct {
	Notes  []NoteSummary `json:"notes"`
	Status MemoryStatus  `json:"status"`
}

type ConsolidateMemoryResult struct {
	PublicAdded        int    `json:"publicAdded"`
	PrivateAdded       int    `json:"privateAdded"`
	PublicManifestCID  string `json:"publicManifestCid,omitempty"`
	PrivateManifestCID string `json:"privateManifestCid,omitempty"`
}

func (s *Service) NotesOverview() (NotesOverview, error) {
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NotesOverview{Notes: []NoteSummary{}}, nil
		}
		return NotesOverview{}, err
	}
	inventory, err := storage.InspectMemory(path, id.SignedState())
	if err != nil {
		return NotesOverview{}, err
	}
	notes := make([]NoteSummary, 0, len(inventory.Public)+len(inventory.Private))
	for _, obj := range append(inventory.Public, inventory.Private...) {
		note := NoteSummary{CID: obj.CID, Type: obj.Type, CreatedAt: obj.CreatedAt, Visibility: obj.Visibility, File: filepath.Join(filepath.Dir(path), obj.CID+".json")}
		if obj.Visibility == types.VisibilityPrivate || obj.Encryption != nil {
			note.Locked = true
		} else {
			note.Preview = obj.Payload
		}
		notes = append(notes, note)
	}
	sort.Slice(notes, func(i, j int) bool { return notes[i].CreatedAt.After(notes[j].CreatedAt) })
	return NotesOverview{
		Notes: notes,
		Status: MemoryStatus{
			LinkedPublic:  len(inventory.Public),
			LinkedPrivate: len(inventory.Private),
			LegacyPublic:  len(inventory.LegacyPublic),
			LegacyPrivate: len(inventory.LegacyPrivate),
		},
	}, nil
}

func (s *Service) ListNotes() ([]NoteSummary, error) {
	overview, err := s.NotesOverview()
	return overview.Notes, err
}

func (s *Service) MemoryStatus() (MemoryStatus, error) {
	overview, err := s.NotesOverview()
	return overview.Status, err
}

func (s *Service) ConsolidateLegacyMemory() (ConsolidateMemoryResult, error) {
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		return ConsolidateMemoryResult{}, err
	}
	inventory, err := storage.InspectMemory(path, id.SignedState())
	if err != nil {
		return ConsolidateMemoryResult{}, err
	}
	if len(inventory.LegacyPublic)+len(inventory.LegacyPrivate) == 0 {
		return ConsolidateMemoryResult{}, nil
	}
	rootPriv, err := id.PreferredRootPrivateKey()
	if err != nil {
		return ConsolidateMemoryResult{}, err
	}

	result := ConsolidateMemoryResult{}
	groups := []struct {
		visibility types.Visibility
		current    []types.MemoryObject
		legacy     []types.MemoryObject
	}{
		{types.VisibilityPublic, inventory.Public, inventory.LegacyPublic},
		{types.VisibilityPrivate, inventory.Private, inventory.LegacyPrivate},
	}
	for _, group := range groups {
		if len(group.legacy) == 0 {
			continue
		}
		items := append(append([]types.MemoryObject(nil), group.current...), group.legacy...)
		manifest, err := memory.NewManifest(group.visibility, items)
		if err != nil {
			return ConsolidateMemoryResult{}, err
		}
		if err := memory.SignManifest(&manifest, rootPriv); err != nil {
			return ConsolidateMemoryResult{}, err
		}
		if err := storage.WriteJSON(filepath.Join(filepath.Dir(path), manifest.CID+".json"), manifest); err != nil {
			return ConsolidateMemoryResult{}, err
		}
		if group.visibility == types.VisibilityPrivate {
			if err := id.AddPrivateMemoryRoot(manifest.CID); err != nil {
				return ConsolidateMemoryResult{}, err
			}
			result.PrivateAdded = len(group.legacy)
			result.PrivateManifestCID = manifest.CID
		} else {
			if err := id.AddPublicMemoryRoot(manifest.CID); err != nil {
				return ConsolidateMemoryResult{}, err
			}
			result.PublicAdded = len(group.legacy)
			result.PublicManifestCID = manifest.CID
		}
	}
	if err := storage.SaveIdentity(path, id); err != nil {
		return ConsolidateMemoryResult{}, err
	}
	return result, nil
}

// SelfCheck proves the current device controls this identity by running a full
// challenge -> respond -> verify against the identity's own public state.
func (s *Service) SelfCheck() (VerificationResult, error) {
	id, _, err := s.loadIdentityWithPath()
	if err != nil {
		return VerificationResult{}, err
	}
	challenge, err := auth.NewChallenge(id.Document.ID, 5*time.Minute)
	if err != nil {
		return VerificationResult{}, err
	}
	response, err := auth.SignChallenge(challenge, "", id)
	if err != nil {
		return VerificationResult{}, err
	}
	return VerifyChallengeResponse(id.SignedState(), response), nil
}

// ExportBackup returns a complete, versioned local backup encrypted with a
// passphrase. It includes the keyring and every object currently referenced by
// the identity.
func (s *Service) ExportBackup(passphrase string) ([]byte, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, errors.New("需要设置备份口令")
	}
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		return nil, err
	}
	inventory, err := storage.InspectMemory(path, id.SignedState())
	if err != nil {
		return nil, err
	}
	legacyCount := len(inventory.LegacyPublic) + len(inventory.LegacyPrivate)
	if legacyCount > 0 {
		return nil, fmt.Errorf("发现 %d 条旧版本地内容尚未纳入当前内容目录，请先在“我的内容”中整理后再备份", legacyCount)
	}
	bundle, err := storage.NewBackupBundle(path, id)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	return icrypto.EncryptWithPassphrase(data, passphrase)
}

// ImportBackup restores a v2 complete backup or a legacy identity-only backup.
func (s *Service) ImportBackup(data []byte, passphrase string) (BackupImportResult, error) {
	if strings.TrimSpace(passphrase) == "" {
		return BackupImportResult{}, errors.New("需要输入备份口令")
	}
	plaintext, err := icrypto.DecryptWithPassphrase(data, passphrase)
	if err != nil {
		return BackupImportResult{}, errors.New("备份口令不正确或文件已损坏")
	}

	var bundle storage.BackupBundle
	if err := json.Unmarshal(plaintext, &bundle); err == nil && bundle.Version != "" {
		if err := storage.RestoreBackupBundle(s.IdentityPath(), bundle); err != nil {
			return BackupImportResult{}, errors.New("完整备份校验失败：" + err.Error())
		}
		return BackupImportResult{Version: bundle.Version, Scope: BackupScopeComplete, RestoredObjectCount: len(bundle.Objects)}, nil
	}

	local, err := identity.UnmarshalLocal(plaintext)
	if err != nil {
		return BackupImportResult{}, errors.New("备份内容不是有效的身份文件")
	}
	if _, err := identity.FromLocal(local); err != nil {
		return BackupImportResult{}, errors.New("备份内容校验失败：" + err.Error())
	}
	if err := storage.WriteFileSafely(s.IdentityPath(), plaintext, 0o600); err != nil {
		return BackupImportResult{}, err
	}
	return BackupImportResult{Version: "1", Scope: BackupScopeIdentityOnly}, nil
}

func (s *Service) AddDevice(label string) (types.KeyRecord, error) {
	if strings.TrimSpace(label) == "" {
		label = "device"
	}
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		return types.KeyRecord{}, err
	}
	record, err := id.AddDevice(label)
	if err != nil {
		return types.KeyRecord{}, err
	}
	return record, storage.SaveIdentity(path, id)
}

func (s *Service) RevokeDevice(keyID, reason string) (VerificationResult, error) {
	if strings.TrimSpace(keyID) == "" {
		return VerificationResult{}, errors.New("需要提供设备 key ID")
	}
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		return VerificationResult{}, err
	}
	if err := id.RevokeDevice(keyID, reason); err != nil {
		return VerificationResult{}, err
	}
	if err := storage.SaveIdentity(path, id); err != nil {
		return VerificationResult{}, err
	}
	return VerificationResult{Valid: true, Message: "device revoked"}, nil
}

func (s *Service) RotateRoot(label string) (types.KeyRecord, error) {
	if strings.TrimSpace(label) == "" {
		label = "rotated-root"
	}
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		return types.KeyRecord{}, err
	}
	record, err := id.RotateRoot(label)
	if err != nil {
		return types.KeyRecord{}, err
	}
	return record, storage.SaveIdentity(path, id)
}

func (s *Service) CreateChallenge(identityID string, ttl time.Duration) (ChallengeResult, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if strings.TrimSpace(identityID) == "" {
		id, _, err := s.loadIdentityWithPath()
		if err != nil {
			return ChallengeResult{}, err
		}
		identityID = id.Document.ID
	}
	challenge, err := auth.NewChallenge(identityID, ttl)
	if err != nil {
		return ChallengeResult{}, err
	}
	return ChallengeResult{Challenge: challenge}, nil
}

func (s *Service) RespondToChallenge(challenge types.Challenge, signerKeyID string) (ChallengeResponseResult, error) {
	id, _, err := s.loadIdentityWithPath()
	if err != nil {
		return ChallengeResponseResult{}, err
	}
	response, err := auth.SignChallenge(challenge, signerKeyID, id)
	if err != nil {
		return ChallengeResponseResult{}, err
	}
	return ChallengeResponseResult{Response: response}, nil
}

func VerifyChallengeResponse(state types.SignedIdentityState, response types.ChallengeResponse) VerificationResult {
	if err := identity.VerifyState(state); err != nil {
		return VerificationResult{Valid: false, Message: "公开状态验证失败：" + err.Error()}
	}
	if auth.VerifyChallenge(response, state.Document) {
		return VerificationResult{Valid: true, Message: "challenge response 已通过公开签名身份状态验证"}
	}
	return VerificationResult{Valid: false, Message: "challenge response 无效、已过期，或由非 active device key 签名"}
}

func (s *Service) IssueAttestation(subjectID, claimType, claimValue, evidenceRef string, validFor time.Duration, outPath string) (AttestationResult, error) {
	if strings.TrimSpace(subjectID) == "" {
		return AttestationResult{}, errors.New("需要提供 subject DID")
	}
	if strings.TrimSpace(claimType) == "" {
		claimType = "known"
	}
	if validFor <= 0 {
		validFor = 24 * time.Hour
	}
	id, _, err := s.loadIdentityWithPath()
	if err != nil {
		return AttestationResult{}, err
	}
	att, err := attestation.New(id.Document.ID, id.Document.RootKeyID, subjectID, claimType, map[string]interface{}{"value": claimValue}, validFor, evidenceRef)
	if err != nil {
		return AttestationResult{}, err
	}
	rootPriv, err := id.PreferredRootPrivateKey()
	if err != nil {
		return AttestationResult{}, err
	}
	if err := attestation.Sign(&att, rootPriv); err != nil {
		return AttestationResult{}, err
	}
	if strings.TrimSpace(outPath) != "" {
		if err := storage.WriteJSON(outPath, att); err != nil {
			return AttestationResult{}, err
		}
	}
	return AttestationResult{Attestation: att, OutFile: outPath}, nil
}

func VerifyAttestationWithState(issuerState types.SignedIdentityState, att types.Attestation) VerificationResult {
	if err := identity.VerifyState(issuerState); err != nil {
		return VerificationResult{Valid: false, Message: "issuer 公开状态验证失败：" + err.Error()}
	}
	pub, err := identity.ResolveKey(issuerState.Document, att.IssuerKeyID)
	if err != nil {
		return VerificationResult{Valid: false, Message: "无法解析 issuer key：" + err.Error()}
	}
	if attestation.Verify(att, pub) {
		return VerificationResult{Valid: true, Message: "attestation 签名与有效期已验证"}
	}
	return VerificationResult{Valid: false, Message: "attestation 无效或已过期"}
}

func (s *Service) AttachAttestation(att types.Attestation) (AttachAttestationResult, error) {
	if strings.TrimSpace(att.CID) == "" {
		return AttachAttestationResult{}, errors.New("需要提供 attestation CID")
	}
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		return AttachAttestationResult{}, err
	}
	cidPath := filepath.Join(filepath.Dir(path), att.CID+".json")
	if err := storage.WriteJSON(cidPath, att); err != nil {
		return AttachAttestationResult{}, err
	}
	if err := id.AttachAttestationRef(att.CID); err != nil {
		return AttachAttestationResult{}, err
	}
	if err := storage.SaveIdentity(path, id); err != nil {
		return AttachAttestationResult{}, err
	}
	return AttachAttestationResult{CID: att.CID, File: cidPath}, nil
}

func (s *Service) StartPublish(listenAddr string, wait time.Duration, includeAttestations bool) (PublishResult, error) {
	if strings.TrimSpace(listenAddr) == "" {
		listenAddr = DefaultP2PListen
	}
	if wait <= 0 {
		wait = 30 * time.Second
	}
	id, path, err := s.loadIdentityWithPath()
	if err != nil {
		return PublishResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	resolver, err := p2p.NewResolver(ctx, listenAddr)
	if err != nil {
		cancel()
		return PublishResult{}, err
	}
	state := id.SignedState()
	stored, err := storage.StoreReferencedObjects(resolver, path, state, includeAttestations)
	if err != nil {
		resolver.Close()
		cancel()
		return PublishResult{}, err
	}
	if err := resolver.PublishState(ctx, state); err != nil {
		resolver.Close()
		cancel()
		return PublishResult{}, err
	}
	addrs := resolver.AddrStrings()
	expiresAt := time.Now().UTC().Add(wait)

	s.mu.Lock()
	if s.publishCancel != nil {
		s.publishCancel()
	}
	if s.publishResolver != nil {
		_ = s.publishResolver.Close()
	}
	s.publishCancel = cancel
	s.publishResolver = resolver
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = resolver.Close()
		s.mu.Lock()
		if s.publishResolver == resolver {
			s.publishResolver = nil
			s.publishCancel = nil
		}
		s.mu.Unlock()
	}()

	return PublishResult{Addresses: addrs, IdentityID: state.Document.ID, StoredObjectCIDs: stored, IncludeAttestations: includeAttestations, PrivateMemoryOmitted: true, ExpiresAt: expiresAt}, nil
}

func (s *Service) ResolveState(peerAddr, identityID string) (ResolveResult, error) {
	if strings.TrimSpace(peerAddr) == "" {
		return ResolveResult{}, errors.New("需要提供 peer multiaddr")
	}
	if strings.TrimSpace(identityID) == "" {
		return ResolveResult{}, errors.New("需要提供身份 DID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resolver, err := p2p.NewResolver(ctx, DefaultP2PListen)
	if err != nil {
		return ResolveResult{}, err
	}
	defer resolver.Close()
	if err := resolver.DialPeer(ctx, peerAddr); err != nil {
		return ResolveResult{}, err
	}
	info, err := peer.AddrInfoFromString(peerAddr)
	if err != nil {
		return ResolveResult{}, err
	}
	state, err := resolver.ResolveRemote(ctx, info.ID, identityID)
	if err != nil {
		return ResolveResult{}, err
	}
	if err := identity.VerifyState(state); err != nil {
		return ResolveResult{}, err
	}
	return ResolveResult{State: state}, nil
}

func ParseSignedState(data string) (types.SignedIdentityState, error) {
	state, err := identity.UnmarshalSignedState([]byte(data))
	if err != nil {
		return types.SignedIdentityState{}, err
	}
	if err := identity.VerifyState(state); err != nil {
		return types.SignedIdentityState{}, err
	}
	return state, nil
}

func ParseChallenge(data string) (types.Challenge, error) {
	var challenge types.Challenge
	if err := json.Unmarshal([]byte(data), &challenge); err != nil {
		return types.Challenge{}, err
	}
	return challenge, nil
}

func ParseChallengeResponse(data string) (types.ChallengeResponse, error) {
	var response types.ChallengeResponse
	if err := json.Unmarshal([]byte(data), &response); err != nil {
		return types.ChallengeResponse{}, err
	}
	return response, nil
}

func ParseAttestation(data string) (types.Attestation, error) {
	var att types.Attestation
	if err := json.Unmarshal([]byte(data), &att); err != nil {
		return types.Attestation{}, err
	}
	return att, nil
}

func (s *Service) loadIdentityWithPath() (*identity.Identity, string, error) {
	path := s.IdentityPath()
	id, err := storage.LoadIdentity(path)
	if err != nil {
		return nil, path, err
	}
	return id, path, nil
}

func buildSummary(path string, id *identity.Identity) LocalSummary {
	localLabels := map[string]string{}
	for _, key := range id.LocalKeys {
		localLabels[key.KeyID] = key.Label
	}
	keys := make([]KeySummary, 0, len(id.Document.ActiveKeys))
	counts := KeyCounts{}
	for _, key := range id.Document.ActiveKeys {
		switch key.Role {
		case types.KeyRoleRoot:
			counts.Root++
		case types.KeyRoleDevice:
			counts.Device++
		case types.KeyRoleEncryption:
			counts.Encryption++
		}
		if !key.RevokedAt.IsZero() {
			counts.Revoked++
		}
		label, hasLocal := localLabels[key.ID]
		keys = append(keys, KeySummary{
			ID:                    key.ID,
			Type:                  key.Type,
			Role:                  key.Role,
			PublicKey:             key.PublicKey,
			AddedAt:               key.AddedAt,
			RevokedAt:             key.RevokedAt,
			RevokedReason:         key.RevokedReason,
			PreferredRoot:         key.ID == id.PreferredRootKeyID,
			PreferredDevice:       key.ID == id.PreferredDeviceKeyID,
			PreferredEncryption:   key.ID == id.PreferredEncryptionKeyID,
			HasLocalPrivateKey:    hasLocal,
			LocalPrivateKeyLabel:  label,
			LocalPrivateKeyHidden: hasLocal,
		})
	}
	return LocalSummary{
		HasIdentity:              true,
		IdentityPath:             path,
		DID:                      id.Document.ID,
		Version:                  id.Document.Version,
		DisplayName:              id.Document.Profile.DisplayName,
		RootKeyID:                id.Document.RootKeyID,
		PreferredRootKeyID:       id.PreferredRootKeyID,
		PreferredDeviceKeyID:     id.PreferredDeviceKeyID,
		PreferredEncryptionKeyID: id.PreferredEncryptionKeyID,
		PublicMemoryRoot:         id.Document.PublicMemoryRoot,
		PrivateMemoryRoot:        id.Document.PrivateMemoryRoot,
		LatestEventID:            id.Document.LatestEventID,
		EventCount:               len(id.Events),
		AttestationCount:         len(id.Document.AttestationRefs),
		KeyCounts:                counts,
		Keys:                     keys,
		Warning:                  "本地 identity 文件包含私钥；默认 UI 只展示 public key 和摘要。",
	}
}
