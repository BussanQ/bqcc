package storage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/example/decentid/internal/attestation"
	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/pkg/types"
)

const BackupVersion2 = "2"

type BackupBundle struct {
	Version  string                 `json:"version"`
	Identity identity.LocalIdentity `json:"identity"`
	Objects  []ReferencedObject     `json:"objects"`
}

func NewBackupBundle(identityFile string, id *identity.Identity) (BackupBundle, error) {
	objects, err := CollectReferencedObjects(identityFile, id.SignedState(), CollectOptions{
		IncludePublic:       true,
		IncludePrivate:      true,
		IncludeAttestations: true,
	})
	if err != nil {
		return BackupBundle{}, err
	}
	return BackupBundle{Version: BackupVersion2, Identity: id.ExportLocal(), Objects: objects}, nil
}

func ValidateBackupBundle(bundle BackupBundle) error {
	if bundle.Version != BackupVersion2 {
		return fmt.Errorf("unsupported backup version %q", bundle.Version)
	}
	identityData, err := json.Marshal(bundle.Identity)
	if err != nil {
		return err
	}
	normalized, err := identity.UnmarshalLocal(identityData)
	if err != nil {
		return fmt.Errorf("decode backup identity: %w", err)
	}
	id, err := identity.FromLocal(normalized)
	if err != nil {
		return fmt.Errorf("verify backup identity: %w", err)
	}
	state := id.SignedState()
	rootKeys, err := rootPublicKeys(state.Document)
	if err != nil {
		return err
	}

	objects := make(map[string]ReferencedObject, len(bundle.Objects))
	for _, object := range bundle.Objects {
		if object.CID == "" || len(object.Data) == 0 {
			return fmt.Errorf("backup contains an empty object")
		}
		if _, exists := objects[object.CID]; exists {
			return fmt.Errorf("backup contains duplicate object %s", object.CID)
		}
		if err := validateBackupObject(object, rootKeys); err != nil {
			return err
		}
		objects[object.CID] = object
	}

	reachable := map[string]bool{}
	validateManifest := func(cid string, visibility types.Visibility) error {
		if cid == "" {
			return nil
		}
		object, ok := objects[cid]
		if !ok || object.Kind != ObjectKindMemoryManifest {
			return fmt.Errorf("backup is missing memory manifest %s", cid)
		}
		var manifest types.MemoryManifest
		if err := json.Unmarshal(object.Data, &manifest); err != nil {
			return err
		}
		if manifest.Visibility != visibility {
			return fmt.Errorf("memory manifest %s has the wrong visibility", cid)
		}
		reachable[cid] = true
		for _, itemCID := range manifest.Items {
			item, ok := objects[itemCID]
			if !ok || item.Kind != ObjectKindMemoryObject {
				return fmt.Errorf("backup is missing memory object %s", itemCID)
			}
			var memoryObject types.MemoryObject
			if err := json.Unmarshal(item.Data, &memoryObject); err != nil {
				return err
			}
			if memoryObject.Visibility != visibility {
				return fmt.Errorf("memory object %s has the wrong visibility", itemCID)
			}
			reachable[itemCID] = true
		}
		return nil
	}
	if err := validateManifest(state.Document.PublicMemoryRoot, types.VisibilityPublic); err != nil {
		return err
	}
	if err := validateManifest(state.Document.PrivateMemoryRoot, types.VisibilityPrivate); err != nil {
		return err
	}
	for _, cid := range state.Document.AttestationRefs {
		object, ok := objects[cid]
		if !ok || object.Kind != ObjectKindAttestation {
			return fmt.Errorf("backup is missing attestation %s", cid)
		}
		reachable[cid] = true
	}
	if len(reachable) != len(objects) {
		return fmt.Errorf("backup contains objects not referenced by the identity")
	}
	return nil
}

func validateBackupObject(object ReferencedObject, rootKeys []ed25519.PublicKey) error {
	switch object.Kind {
	case ObjectKindMemoryManifest:
		var manifest types.MemoryManifest
		if err := json.Unmarshal(object.Data, &manifest); err != nil {
			return fmt.Errorf("decode memory manifest %s: %w", object.CID, err)
		}
		computed, err := memory.ManifestCID(manifest)
		if err != nil || manifest.CID != object.CID || computed != object.CID || !verifyManifestWithAnyRoot(manifest, rootKeys) {
			return fmt.Errorf("memory manifest %s failed verification", object.CID)
		}
	case ObjectKindMemoryObject:
		var memoryObject types.MemoryObject
		if err := json.Unmarshal(object.Data, &memoryObject); err != nil {
			return fmt.Errorf("decode memory object %s: %w", object.CID, err)
		}
		computed, err := memory.ObjectCID(memoryObject)
		if err != nil || memoryObject.CID != object.CID || computed != object.CID || !verifyObjectWithAnyRoot(memoryObject, rootKeys) {
			return fmt.Errorf("memory object %s failed verification", object.CID)
		}
	case ObjectKindAttestation:
		var att types.Attestation
		if err := json.Unmarshal(object.Data, &att); err != nil {
			return fmt.Errorf("decode attestation %s: %w", object.CID, err)
		}
		computed, err := attestation.AttestationCID(att)
		if err != nil || att.CID != object.CID || computed != object.CID {
			return fmt.Errorf("attestation %s failed CID verification", object.CID)
		}
	default:
		return fmt.Errorf("unsupported backup object kind %q", object.Kind)
	}
	return nil
}

func RestoreBackupBundle(identityFile string, bundle BackupBundle) error {
	if err := ValidateBackupBundle(bundle); err != nil {
		return err
	}
	baseDir := filepath.Dir(identityFile)
	missing := make([]ReferencedObject, 0, len(bundle.Objects))
	for _, object := range bundle.Objects {
		path := filepath.Join(baseDir, object.CID+".json")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			missing = append(missing, object)
			continue
		}
		if err != nil {
			return err
		}
		equal, compareErr := jsonEqual(data, object.Data)
		if compareErr != nil || !equal {
			return fmt.Errorf("existing object %s conflicts with the backup", object.CID)
		}
	}
	for _, object := range missing {
		path := filepath.Join(baseDir, object.CID+".json")
		if err := WriteFileSafely(path, object.Data, 0o600); err != nil {
			return err
		}
	}
	identityData, err := identity.MarshalLocal(bundle.Identity)
	if err != nil {
		return err
	}
	return WriteFileSafely(identityFile, identityData, 0o600)
}

func jsonEqual(a, b []byte) (bool, error) {
	if bytes.Equal(a, b) {
		return true, nil
	}
	var left interface{}
	if err := json.Unmarshal(a, &left); err != nil {
		return false, err
	}
	var right interface{}
	if err := json.Unmarshal(b, &right); err != nil {
		return false, err
	}
	leftJSON, err := icrypto.CanonicalJSON(left)
	if err != nil {
		return false, err
	}
	rightJSON, err := icrypto.CanonicalJSON(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftJSON, rightJSON), nil
}
