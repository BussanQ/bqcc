package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	icrypto "github.com/example/decentid/internal/crypto"
	"github.com/example/decentid/pkg/types"
)

type PrivateKeyRecord struct {
	KeyID      string
	Type       string
	Role       types.KeyRole
	PrivateKey []byte
	Label      string
}

type Identity struct {
	Document                 types.IdentityDocument
	Events                   []types.IdentityEvent
	LocalKeys                []PrivateKeyRecord
	PreferredRootKeyID       string
	PreferredDeviceKeyID     string
	PreferredEncryptionKeyID string
}

func New(displayName string) (*Identity, error) {
	rootPub, rootPriv, err := icrypto.GenerateEd25519Keypair()
	if err != nil {
		return nil, err
	}
	devicePub, devicePriv, err := icrypto.GenerateEd25519Keypair()
	if err != nil {
		return nil, err
	}
	encryptionPub, encryptionPriv, err := icrypto.GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	identityID := icrypto.DIDFromPublicKey(rootPub)
	rootKeyID := icrypto.HashString("key:" + icrypto.PublicKeyString(rootPub))
	deviceKeyID := icrypto.HashString("key:" + icrypto.PublicKeyString(devicePub))
	encryptionKeyID := icrypto.HashString("key:" + icrypto.BytesString(encryptionPub))
	rootRecord := types.KeyRecord{ID: rootKeyID, Type: "ed25519", Role: types.KeyRoleRoot, PublicKey: icrypto.PublicKeyString(rootPub), AddedAt: now}
	deviceRecord := types.KeyRecord{ID: deviceKeyID, Type: "ed25519", Role: types.KeyRoleDevice, PublicKey: icrypto.PublicKeyString(devicePub), AddedAt: now}
	encryptionRecord := types.KeyRecord{ID: encryptionKeyID, Type: "x25519", Role: types.KeyRoleEncryption, PublicKey: icrypto.BytesString(encryptionPub), AddedAt: now}
	doc := types.IdentityDocument{
		ID:         identityID,
		Version:    "2",
		CreatedAt:  now,
		UpdatedAt:  now,
		RootKeyID:  rootKeyID,
		ActiveKeys: []types.KeyRecord{rootRecord, deviceRecord, encryptionRecord},
		Profile:    types.Profile{DisplayName: displayName},
	}
	createPayload := map[string]interface{}{
		"rootKey":       keyPayload(rootRecord),
		"deviceKey":     keyPayload(deviceRecord),
		"encryptionKey": keyPayload(encryptionRecord),
		"profile": map[string]interface{}{
			"displayName": displayName,
			"bio":         "",
			"attributes":  map[string]string{},
		},
	}
	event, err := NewEvent(types.EventCreateIdentity, identityID, "", rootKeyID, createPayload, rootPriv)
	if err != nil {
		return nil, err
	}
	doc.LatestEventID = event.ID
	return &Identity{
		Document:                 doc,
		Events:                   []types.IdentityEvent{event},
		LocalKeys:                []PrivateKeyRecord{{KeyID: rootKeyID, Type: "ed25519", Role: types.KeyRoleRoot, PrivateKey: []byte(rootPriv), Label: "root"}, {KeyID: deviceKeyID, Type: "ed25519", Role: types.KeyRoleDevice, PrivateKey: []byte(devicePriv), Label: "device"}, {KeyID: encryptionKeyID, Type: "x25519", Role: types.KeyRoleEncryption, PrivateKey: encryptionPriv, Label: "encryption"}},
		PreferredRootKeyID:       rootKeyID,
		PreferredDeviceKeyID:     deviceKeyID,
		PreferredEncryptionKeyID: encryptionKeyID,
	}, nil
}

// eventSigningBase builds the canonical pre-image signed/verified for an
// identity event. Shared by NewEvent and VerifyEvent so they cannot drift.
func eventSigningBase(eventType types.EventType, identityID, prevEventID, signerKeyID string, timestamp time.Time, payload map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type":        eventType,
		"identityId":  identityID,
		"prevEventId": prevEventID,
		"signerKeyId": signerKeyID,
		"timestamp":   timestamp.Format(time.RFC3339Nano),
		"payload":     payload,
	}
}

func NewEvent(eventType types.EventType, identityID, prevEventID, signerKeyID string, payload map[string]interface{}, priv ed25519.PrivateKey) (types.IdentityEvent, error) {
	now := time.Now().UTC()
	encoded, err := icrypto.CanonicalJSON(eventSigningBase(eventType, identityID, prevEventID, signerKeyID, now, payload))
	if err != nil {
		return types.IdentityEvent{}, err
	}
	eventID := icrypto.HashString("event:" + icrypto.HashBytes(encoded))
	sig := icrypto.SignBytes(priv, encoded)
	return types.IdentityEvent{ID: eventID, Type: eventType, IdentityID: identityID, PrevEventID: prevEventID, SignerKeyID: signerKeyID, Timestamp: now, Payload: payload, Signature: sig}, nil
}

func VerifyEvent(event types.IdentityEvent, pub ed25519.PublicKey) bool {
	encoded, err := icrypto.CanonicalJSON(eventSigningBase(event.Type, event.IdentityID, event.PrevEventID, event.SignerKeyID, event.Timestamp, event.Payload))
	if err != nil {
		return false
	}
	return icrypto.VerifyBytes(pub, encoded, event.Signature)
}

func (i *Identity) UpdateProfile(profile types.Profile) error {
	rootPriv, err := i.PreferredRootPrivateKey()
	if err != nil {
		return err
	}
	payload := map[string]interface{}{"profile": profilePayload(profile)}
	event, err := NewEvent(types.EventUpdateProfile, i.Document.ID, i.Document.LatestEventID, i.Document.RootKeyID, payload, rootPriv)
	if err != nil {
		return err
	}
	i.Events = append(i.Events, event)
	return i.refreshDocument()
}

func (i *Identity) AddPublicMemoryRoot(cid string) error {
	return i.updateMemoryRoot("public", cid)
}

func (i *Identity) AddPrivateMemoryRoot(cid string) error {
	return i.updateMemoryRoot("private", cid)
}

func (i *Identity) updateMemoryRoot(kind, cid string) error {
	rootPriv, err := i.PreferredRootPrivateKey()
	if err != nil {
		return err
	}
	payload := map[string]interface{}{"kind": kind, "cid": cid}
	event, err := NewEvent(types.EventUpdateMemory, i.Document.ID, i.Document.LatestEventID, i.Document.RootKeyID, payload, rootPriv)
	if err != nil {
		return err
	}
	i.Events = append(i.Events, event)
	return i.refreshDocument()
}

func (i *Identity) AddDevice(label string) (types.KeyRecord, error) {
	pub, priv, err := icrypto.GenerateEd25519Keypair()
	if err != nil {
		return types.KeyRecord{}, err
	}
	record := types.KeyRecord{ID: icrypto.HashString("key:" + icrypto.PublicKeyString(pub)), Type: "ed25519", Role: types.KeyRoleDevice, PublicKey: icrypto.PublicKeyString(pub), AddedAt: time.Now().UTC()}
	rootPriv, err := i.PreferredRootPrivateKey()
	if err != nil {
		return types.KeyRecord{}, err
	}
	event, err := NewEvent(types.EventAddDeviceKey, i.Document.ID, i.Document.LatestEventID, i.Document.RootKeyID, map[string]interface{}{"key": keyPayload(record)}, rootPriv)
	if err != nil {
		return types.KeyRecord{}, err
	}
	i.Events = append(i.Events, event)
	i.LocalKeys = append(i.LocalKeys, PrivateKeyRecord{KeyID: record.ID, Type: record.Type, Role: record.Role, PrivateKey: []byte(priv), Label: label})
	if i.PreferredDeviceKeyID == "" {
		i.PreferredDeviceKeyID = record.ID
	}
	return record, i.refreshDocument()
}

func (i *Identity) RevokeDevice(keyID, reason string) error {
	rootPriv, err := i.PreferredRootPrivateKey()
	if err != nil {
		return err
	}
	event, err := NewEvent(types.EventRevokeDevice, i.Document.ID, i.Document.LatestEventID, i.Document.RootKeyID, map[string]interface{}{"keyId": keyID, "reason": reason}, rootPriv)
	if err != nil {
		return err
	}
	i.Events = append(i.Events, event)
	if err := i.refreshDocument(); err != nil {
		return err
	}
	if i.PreferredDeviceKeyID == keyID {
		i.PreferredDeviceKeyID = i.DeviceKeyID()
	}
	return nil
}

func (i *Identity) RotateRoot(label string) (types.KeyRecord, error) {
	pub, priv, err := icrypto.GenerateEd25519Keypair()
	if err != nil {
		return types.KeyRecord{}, err
	}
	newRecord := types.KeyRecord{ID: icrypto.HashString("key:" + icrypto.PublicKeyString(pub)), Type: "ed25519", Role: types.KeyRoleRoot, PublicKey: icrypto.PublicKeyString(pub), AddedAt: time.Now().UTC()}
	oldRootKeyID := i.Document.RootKeyID
	rootPriv, err := i.PreferredRootPrivateKey()
	if err != nil {
		return types.KeyRecord{}, err
	}
	event, err := NewEvent(types.EventRotateRootKey, i.Document.ID, i.Document.LatestEventID, oldRootKeyID, map[string]interface{}{"newRootKey": keyPayload(newRecord), "oldRootKeyId": oldRootKeyID}, rootPriv)
	if err != nil {
		return types.KeyRecord{}, err
	}
	i.Events = append(i.Events, event)
	i.LocalKeys = append(i.LocalKeys, PrivateKeyRecord{KeyID: newRecord.ID, Type: newRecord.Type, Role: newRecord.Role, PrivateKey: []byte(priv), Label: label})
	i.PreferredRootKeyID = newRecord.ID
	return newRecord, i.refreshDocument()
}

func (i *Identity) AttachAttestationRef(cid string) error {
	rootPriv, err := i.PreferredRootPrivateKey()
	if err != nil {
		return err
	}
	event, err := NewEvent(types.EventAttachProof, i.Document.ID, i.Document.LatestEventID, i.Document.RootKeyID, map[string]interface{}{"cid": cid}, rootPriv)
	if err != nil {
		return err
	}
	i.Events = append(i.Events, event)
	return i.refreshDocument()
}

func (i *Identity) DeviceKeyID() string {
	if i.PreferredDeviceKeyID != "" {
		if _, err := ResolveKey(i.Document, i.PreferredDeviceKeyID); err == nil {
			return i.PreferredDeviceKeyID
		}
	}
	for _, key := range i.Document.ActiveKeys {
		if key.Role == types.KeyRoleDevice && key.RevokedAt.IsZero() {
			return key.ID
		}
	}
	return ""
}

func (i *Identity) EncryptionKeyID() string {
	if i.PreferredEncryptionKeyID != "" {
		if _, err := ResolveEncryptionPublicKey(i.Document, i.PreferredEncryptionKeyID); err == nil {
			return i.PreferredEncryptionKeyID
		}
	}
	for _, key := range i.Document.ActiveKeys {
		if key.Role == types.KeyRoleEncryption && key.RevokedAt.IsZero() {
			return key.ID
		}
	}
	return ""
}

func ResolveKey(doc types.IdentityDocument, keyID string) (ed25519.PublicKey, error) {
	for _, key := range doc.ActiveKeys {
		if key.ID == keyID {
			if !key.RevokedAt.IsZero() {
				return nil, fmt.Errorf("key revoked")
			}
			if key.Type != "ed25519" {
				return nil, fmt.Errorf("key %s is not ed25519", keyID)
			}
			return icrypto.ParsePublicKey(key.PublicKey)
		}
	}
	return nil, fmt.Errorf("key not found")
}

func ResolveEncryptionPublicKey(doc types.IdentityDocument, keyID string) ([]byte, error) {
	for _, key := range doc.ActiveKeys {
		if key.ID == keyID {
			if !key.RevokedAt.IsZero() {
				return nil, fmt.Errorf("key revoked")
			}
			if key.Type != "x25519" {
				return nil, fmt.Errorf("key %s is not x25519", keyID)
			}
			return icrypto.ParseBytes(key.PublicKey)
		}
	}
	return nil, fmt.Errorf("key not found")
}

func VerifyState(state types.SignedIdentityState) error {
	rebuilt, err := ReplayState(state.Events)
	if err != nil {
		return err
	}
	if !documentsEqual(rebuilt, state.Document) {
		return errors.New("document does not match replayed state")
	}
	return nil
}

func ReplayState(events []types.IdentityEvent) (types.IdentityDocument, error) {
	if len(events) == 0 {
		return types.IdentityDocument{}, errors.New("missing events")
	}
	if events[0].Type != types.EventCreateIdentity {
		return types.IdentityDocument{}, errors.New("first event must be CreateIdentity")
	}
	doc, err := initDocumentFromCreate(events[0])
	if err != nil {
		return types.IdentityDocument{}, err
	}
	for idx, event := range events {
		if idx == 0 {
			pub, err := ResolveKey(doc, event.SignerKeyID)
			if err != nil {
				return types.IdentityDocument{}, err
			}
			if !VerifyEvent(event, pub) {
				return types.IdentityDocument{}, fmt.Errorf("invalid signature for event %s", event.ID)
			}
			if event.SignerKeyID != doc.RootKeyID {
				return types.IdentityDocument{}, fmt.Errorf("event %s not signed by active root key", event.ID)
			}
			continue
		}
		if event.PrevEventID != events[idx-1].ID {
			return types.IdentityDocument{}, fmt.Errorf("broken event chain at %s", event.ID)
		}
		if event.Timestamp.Before(events[idx-1].Timestamp) {
			return types.IdentityDocument{}, fmt.Errorf("non-monotonic timestamp at event %s", event.ID)
		}
		pub, err := ResolveKey(doc, event.SignerKeyID)
		if err != nil {
			return types.IdentityDocument{}, err
		}
		if !VerifyEvent(event, pub) {
			return types.IdentityDocument{}, fmt.Errorf("invalid signature for event %s", event.ID)
		}
		// Management events must be signed by the active root key as it stands
		// before this event is applied (RotateRootKey is signed by the old root).
		if event.SignerKeyID != doc.RootKeyID {
			return types.IdentityDocument{}, fmt.Errorf("event %s not signed by active root key", event.ID)
		}
		if err := applyEvent(&doc, event); err != nil {
			return types.IdentityDocument{}, err
		}
	}
	doc.LatestEventID = events[len(events)-1].ID
	return doc, nil
}

func initDocumentFromCreate(event types.IdentityEvent) (types.IdentityDocument, error) {
	root, err := keyRecordFromPayload(event.Payload["rootKey"])
	if err != nil {
		return types.IdentityDocument{}, err
	}
	device, err := keyRecordFromPayload(event.Payload["deviceKey"])
	if err != nil {
		return types.IdentityDocument{}, err
	}
	encryption, err := keyRecordFromPayload(event.Payload["encryptionKey"])
	if err != nil {
		return types.IdentityDocument{}, err
	}
	profileMap, ok := event.Payload["profile"].(map[string]interface{})
	if !ok {
		return types.IdentityDocument{}, errors.New("missing profile in create event")
	}
	rootPub, err := icrypto.ParsePublicKey(root.PublicKey)
	if err != nil {
		return types.IdentityDocument{}, fmt.Errorf("invalid root public key: %w", err)
	}
	if icrypto.DIDFromPublicKey(rootPub) != event.IdentityID {
		return types.IdentityDocument{}, errors.New("identity id does not match root key")
	}
	profile := profileFromPayload(profileMap)
	doc := types.IdentityDocument{ID: event.IdentityID, Version: "2", CreatedAt: event.Timestamp, UpdatedAt: event.Timestamp, RootKeyID: root.ID, ActiveKeys: []types.KeyRecord{root, device, encryption}, Profile: profile, LatestEventID: event.ID}
	pub, err := ResolveKey(doc, event.SignerKeyID)
	if err != nil {
		return types.IdentityDocument{}, err
	}
	if !VerifyEvent(event, pub) {
		return types.IdentityDocument{}, errors.New("invalid create signature")
	}
	return doc, nil
}

func applyEvent(doc *types.IdentityDocument, event types.IdentityEvent) error {
	doc.UpdatedAt = event.Timestamp
	doc.LatestEventID = event.ID
	switch event.Type {
	case types.EventCreateIdentity:
		return nil
	case types.EventUpdateProfile:
		profileMap, ok := event.Payload["profile"].(map[string]interface{})
		if !ok {
			return errors.New("invalid profile payload")
		}
		doc.Profile = profileFromPayload(profileMap)
	case types.EventUpdateMemory:
		kind, _ := event.Payload["kind"].(string)
		cid, _ := event.Payload["cid"].(string)
		switch kind {
		case "public":
			doc.PublicMemoryRoot = cid
		case "private":
			doc.PrivateMemoryRoot = cid
		default:
			return fmt.Errorf("unknown memory kind: %s", kind)
		}
	case types.EventAddDeviceKey:
		record, err := keyRecordFromPayload(event.Payload["key"])
		if err != nil {
			return err
		}
		doc.ActiveKeys = append(doc.ActiveKeys, record)
	case types.EventRevokeDevice:
		keyID, _ := event.Payload["keyId"].(string)
		reason, _ := event.Payload["reason"].(string)
		for idx := range doc.ActiveKeys {
			if doc.ActiveKeys[idx].ID == keyID {
				doc.ActiveKeys[idx].RevokedAt = event.Timestamp
				doc.ActiveKeys[idx].RevokedReason = reason
				return nil
			}
		}
		return fmt.Errorf("key not found for revoke: %s", keyID)
	case types.EventRotateRootKey:
		newRoot, err := keyRecordFromPayload(event.Payload["newRootKey"])
		if err != nil {
			return err
		}
		oldRootID, _ := event.Payload["oldRootKeyId"].(string)
		for idx := range doc.ActiveKeys {
			if doc.ActiveKeys[idx].ID == oldRootID {
				doc.ActiveKeys[idx].RevokedAt = event.Timestamp
				break
			}
		}
		doc.ActiveKeys = append(doc.ActiveKeys, newRoot)
		doc.RootKeyID = newRoot.ID
	case types.EventAttachProof:
		cid, _ := event.Payload["cid"].(string)
		if cid == "" {
			return errors.New("missing attestation cid")
		}
		if !slices.Contains(doc.AttestationRefs, cid) {
			doc.AttestationRefs = append(doc.AttestationRefs, cid)
		}
	default:
		return fmt.Errorf("unsupported event type: %s", event.Type)
	}
	return nil
}

func documentsEqual(a, b types.IdentityDocument) bool {
	if a.ID != b.ID || a.Version != b.Version || !a.CreatedAt.Equal(b.CreatedAt) || !a.UpdatedAt.Equal(b.UpdatedAt) || a.RootKeyID != b.RootKeyID || a.PublicMemoryRoot != b.PublicMemoryRoot || a.PrivateMemoryRoot != b.PrivateMemoryRoot || a.LatestEventID != b.LatestEventID {
		return false
	}
	if a.Profile.DisplayName != b.Profile.DisplayName || a.Profile.Bio != b.Profile.Bio {
		return false
	}
	if !mapsEqual(a.Profile.Attributes, b.Profile.Attributes) {
		return false
	}
	if len(a.ActiveKeys) != len(b.ActiveKeys) || len(a.AttestationRefs) != len(b.AttestationRefs) {
		return false
	}
	for idx := range a.ActiveKeys {
		if a.ActiveKeys[idx] != b.ActiveKeys[idx] {
			return false
		}
	}
	for idx := range a.AttestationRefs {
		if a.AttestationRefs[idx] != b.AttestationRefs[idx] {
			return false
		}
	}
	return true
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func profilePayload(profile types.Profile) map[string]interface{} {
	attributes := map[string]string{}
	for key, value := range profile.Attributes {
		attributes[key] = value
	}
	return map[string]interface{}{"displayName": profile.DisplayName, "bio": profile.Bio, "attributes": attributes}
}

func profileFromPayload(payload map[string]interface{}) types.Profile {
	profile := types.Profile{}
	if displayName, ok := payload["displayName"].(string); ok {
		profile.DisplayName = displayName
	}
	if bio, ok := payload["bio"].(string); ok {
		profile.Bio = bio
	}
	attributes := map[string]string{}
	if rawAttributes, ok := payload["attributes"].(map[string]interface{}); ok {
		for key, value := range rawAttributes {
			if str, ok := value.(string); ok {
				attributes[key] = str
			}
		}
	}
	profile.Attributes = attributes
	return profile
}

func keyPayload(record types.KeyRecord) map[string]interface{} {
	payload := map[string]interface{}{"id": record.ID, "type": record.Type, "role": string(record.Role), "publicKey": record.PublicKey, "addedAt": record.AddedAt.Format(time.RFC3339Nano)}
	if !record.RevokedAt.IsZero() {
		payload["revokedAt"] = record.RevokedAt.Format(time.RFC3339Nano)
	}
	if record.RevokedReason != "" {
		payload["revokedReason"] = record.RevokedReason
	}
	return payload
}

func keyRecordFromPayload(raw interface{}) (types.KeyRecord, error) {
	payload, ok := raw.(map[string]interface{})
	if !ok {
		return types.KeyRecord{}, errors.New("invalid key payload")
	}
	record := types.KeyRecord{}
	if id, ok := payload["id"].(string); ok {
		record.ID = id
	}
	if typ, ok := payload["type"].(string); ok {
		record.Type = typ
	}
	if role, ok := payload["role"].(string); ok {
		record.Role = types.KeyRole(role)
	}
	if pub, ok := payload["publicKey"].(string); ok {
		record.PublicKey = pub
	}
	if addedAt, ok := payload["addedAt"].(string); ok {
		parsed, err := time.Parse(time.RFC3339Nano, addedAt)
		if err != nil {
			return types.KeyRecord{}, err
		}
		record.AddedAt = parsed
	}
	if revokedAt, ok := payload["revokedAt"].(string); ok && revokedAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, revokedAt)
		if err != nil {
			return types.KeyRecord{}, err
		}
		record.RevokedAt = parsed
	}
	if reason, ok := payload["revokedReason"].(string); ok {
		record.RevokedReason = reason
	}
	return record, nil
}

func (i *Identity) refreshDocument() error {
	doc, err := ReplayState(i.Events)
	if err != nil {
		return err
	}
	i.Document = doc
	return nil
}
