package storage

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/example/decentid/internal/attestation"
	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/pkg/types"
)

type ObjectKind string

const (
	ObjectKindMemoryManifest ObjectKind = "memory-manifest"
	ObjectKindMemoryObject   ObjectKind = "memory-object"
	ObjectKindAttestation    ObjectKind = "attestation"
)

type ReferencedObject struct {
	CID  string          `json:"cid"`
	Kind ObjectKind      `json:"kind"`
	Data json.RawMessage `json:"data"`
}

type CollectOptions struct {
	IncludePublic       bool
	IncludePrivate      bool
	IncludeAttestations bool
}

type MemoryInventory struct {
	Public        []types.MemoryObject
	Private       []types.MemoryObject
	LegacyPublic  []types.MemoryObject
	LegacyPrivate []types.MemoryObject
}

func CollectReferencedObjects(identityFile string, state types.SignedIdentityState, options CollectOptions) ([]ReferencedObject, error) {
	rootKeys, err := verifiedRootPublicKeys(state)
	if err != nil {
		return nil, err
	}

	baseDir := filepath.Dir(identityFile)
	objects := make([]ReferencedObject, 0)
	seen := map[string]bool{}
	appendObjects := func(items []ReferencedObject) {
		for _, object := range items {
			if seen[object.CID] {
				continue
			}
			seen[object.CID] = true
			objects = append(objects, object)
		}
	}

	if options.IncludePublic && state.Document.PublicMemoryRoot != "" {
		items, _, err := collectManifestObjects(baseDir, state.Document.PublicMemoryRoot, types.VisibilityPublic, rootKeys)
		if err != nil {
			return nil, err
		}
		appendObjects(items)
	}
	if options.IncludePrivate && state.Document.PrivateMemoryRoot != "" {
		items, _, err := collectManifestObjects(baseDir, state.Document.PrivateMemoryRoot, types.VisibilityPrivate, rootKeys)
		if err != nil {
			return nil, err
		}
		appendObjects(items)
	}
	if options.IncludeAttestations {
		for _, cid := range state.Document.AttestationRefs {
			data, err := readCIDFile(baseDir, cid)
			if err != nil {
				return nil, fmt.Errorf("read attestation %s: %w", cid, err)
			}
			var att types.Attestation
			if err := json.Unmarshal(data, &att); err != nil {
				return nil, fmt.Errorf("decode attestation %s: %w", cid, err)
			}
			computed, err := attestation.AttestationCID(att)
			if err != nil || att.CID != cid || computed != cid {
				return nil, fmt.Errorf("attestation %s failed CID verification", cid)
			}
			appendObjects([]ReferencedObject{{CID: cid, Kind: ObjectKindAttestation, Data: data}})
		}
	}
	return objects, nil
}

func LoadCurrentMemoryObjects(identityFile string, state types.SignedIdentityState, visibility types.Visibility) ([]types.MemoryObject, error) {
	rootKeys, err := verifiedRootPublicKeys(state)
	if err != nil {
		return nil, err
	}
	cid, err := memoryRoot(state.Document, visibility)
	if err != nil || cid == "" {
		return []types.MemoryObject{}, err
	}
	_, objects, err := collectManifestObjects(filepath.Dir(identityFile), cid, visibility, rootKeys)
	return objects, err
}

// InspectMemory reads each current manifest once and returns current and valid
// unlinked legacy objects for the identity.
func InspectMemory(identityFile string, state types.SignedIdentityState) (MemoryInventory, error) {
	rootKeys, err := verifiedRootPublicKeys(state)
	if err != nil {
		return MemoryInventory{}, err
	}
	baseDir := filepath.Dir(identityFile)
	inventory := MemoryInventory{}
	if state.Document.PublicMemoryRoot != "" {
		_, inventory.Public, err = collectManifestObjects(baseDir, state.Document.PublicMemoryRoot, types.VisibilityPublic, rootKeys)
		if err != nil {
			return MemoryInventory{}, err
		}
	}
	if state.Document.PrivateMemoryRoot != "" {
		_, inventory.Private, err = collectManifestObjects(baseDir, state.Document.PrivateMemoryRoot, types.VisibilityPrivate, rootKeys)
		if err != nil {
			return MemoryInventory{}, err
		}
	}
	linked := make(map[string]bool, len(inventory.Public)+len(inventory.Private))
	for _, object := range inventory.Public {
		linked[object.CID] = true
	}
	for _, object := range inventory.Private {
		linked[object.CID] = true
	}
	legacy, err := scanLegacyMemoryObjects(identityFile, linked, rootKeys)
	if err != nil {
		return MemoryInventory{}, err
	}
	for _, object := range legacy {
		if object.Visibility == types.VisibilityPrivate {
			inventory.LegacyPrivate = append(inventory.LegacyPrivate, object)
		} else {
			inventory.LegacyPublic = append(inventory.LegacyPublic, object)
		}
	}
	return inventory, nil
}

func collectManifestObjects(baseDir, cid string, visibility types.Visibility, rootKeys []ed25519.PublicKey) ([]ReferencedObject, []types.MemoryObject, error) {
	data, err := readCIDFile(baseDir, cid)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s memory manifest %s: %w", visibility, cid, err)
	}
	var manifest types.MemoryManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("decode memory manifest %s: %w", cid, err)
	}
	computed, err := memory.ManifestCID(manifest)
	if err != nil || manifest.CID != cid || computed != cid || manifest.Visibility != visibility {
		return nil, nil, fmt.Errorf("memory manifest %s failed integrity verification", cid)
	}
	if !verifyManifestWithAnyRoot(manifest, rootKeys) {
		return nil, nil, fmt.Errorf("memory manifest %s signature is not from this identity", cid)
	}

	referenced := make([]ReferencedObject, 0, len(manifest.Items)+1)
	typed := make([]types.MemoryObject, 0, len(manifest.Items))
	referenced = append(referenced, ReferencedObject{CID: cid, Kind: ObjectKindMemoryManifest, Data: data})
	seen := map[string]bool{}
	for _, itemCID := range manifest.Items {
		if itemCID == "" || seen[itemCID] {
			return nil, nil, fmt.Errorf("memory manifest %s contains an empty or duplicate item", cid)
		}
		seen[itemCID] = true
		itemData, err := readCIDFile(baseDir, itemCID)
		if err != nil {
			return nil, nil, fmt.Errorf("read memory object %s: %w", itemCID, err)
		}
		var object types.MemoryObject
		if err := json.Unmarshal(itemData, &object); err != nil {
			return nil, nil, fmt.Errorf("decode memory object %s: %w", itemCID, err)
		}
		computed, err := memory.ObjectCID(object)
		if err != nil || object.CID != itemCID || computed != itemCID || object.Visibility != visibility {
			return nil, nil, fmt.Errorf("memory object %s failed integrity verification", itemCID)
		}
		if !verifyObjectWithAnyRoot(object, rootKeys) {
			return nil, nil, fmt.Errorf("memory object %s signature is not from this identity", itemCID)
		}
		referenced = append(referenced, ReferencedObject{CID: itemCID, Kind: ObjectKindMemoryObject, Data: itemData})
		typed = append(typed, object)
	}
	return referenced, typed, nil
}

func scanLegacyMemoryObjects(identityFile string, linked map[string]bool, rootKeys []ed25519.PublicKey) ([]types.MemoryObject, error) {
	baseDir := filepath.Dir(identityFile)
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}
	identityName := filepath.Base(identityFile)
	legacy := make([]types.MemoryObject, 0)
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == identityName || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(baseDir, entry.Name()))
		if err != nil {
			continue
		}
		var object types.MemoryObject
		if json.Unmarshal(data, &object) != nil || object.CID == "" || linked[object.CID] {
			continue
		}
		if entry.Name() != object.CID+".json" {
			continue
		}
		if object.Visibility != types.VisibilityPublic && object.Visibility != types.VisibilityPrivate {
			continue
		}
		computed, err := memory.ObjectCID(object)
		if err != nil || computed != object.CID || !verifyObjectWithAnyRoot(object, rootKeys) {
			continue
		}
		legacy = append(legacy, object)
	}
	sort.Slice(legacy, func(i, j int) bool {
		if legacy[i].CreatedAt.Equal(legacy[j].CreatedAt) {
			return legacy[i].CID < legacy[j].CID
		}
		return legacy[i].CreatedAt.Before(legacy[j].CreatedAt)
	})
	return legacy, nil
}

func memoryRoot(doc types.IdentityDocument, visibility types.Visibility) (string, error) {
	switch visibility {
	case types.VisibilityPublic:
		return doc.PublicMemoryRoot, nil
	case types.VisibilityPrivate:
		return doc.PrivateMemoryRoot, nil
	default:
		return "", fmt.Errorf("unsupported memory visibility %q", visibility)
	}
}

func readCIDFile(baseDir, cid string) ([]byte, error) {
	if filepath.Base(cid) != cid || cid == "." || cid == ".." {
		return nil, fmt.Errorf("invalid CID %q", cid)
	}
	return os.ReadFile(filepath.Join(baseDir, cid+".json"))
}

func verifiedRootPublicKeys(state types.SignedIdentityState) ([]ed25519.PublicKey, error) {
	if err := identity.VerifyState(state); err != nil {
		return nil, fmt.Errorf("verify identity state: %w", err)
	}
	return rootPublicKeys(state.Document)
}

func rootPublicKeys(doc types.IdentityDocument) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0)
	for _, key := range doc.ActiveKeys {
		if key.Role != types.KeyRoleRoot || key.Type != "ed25519" {
			continue
		}
		pub, err := icrypto.ParsePublicKey(key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("parse root key %s: %w", key.ID, err)
		}
		keys = append(keys, pub)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("identity has no root public key")
	}
	return keys, nil
}

func verifyManifestWithAnyRoot(manifest types.MemoryManifest, rootKeys []ed25519.PublicKey) bool {
	for _, key := range rootKeys {
		if memory.VerifyManifest(manifest, key) {
			return true
		}
	}
	return false
}

func verifyObjectWithAnyRoot(object types.MemoryObject, rootKeys []ed25519.PublicKey) bool {
	for _, key := range rootKeys {
		if memory.VerifyObject(object, key) {
			return true
		}
	}
	return false
}
