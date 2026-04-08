package types

import "time"

type Visibility string

const (
	VisibilityPublic  Visibility = "public"
	VisibilityPrivate Visibility = "private"
	VisibilityShared  Visibility = "shared"
)

type EventType string

const (
	EventCreateIdentity EventType = "CreateIdentity"
	EventAddDeviceKey   EventType = "AddDeviceKey"
	EventRevokeDevice   EventType = "RevokeDeviceKey"
	EventRotateRootKey  EventType = "RotateRootKey"
	EventUpdateProfile  EventType = "UpdateProfile"
	EventUpdateMemory   EventType = "UpdateMemoryRoot"
	EventAttachProof    EventType = "AttachAttestation"
)

type KeyRole string

const (
	KeyRoleRoot       KeyRole = "root"
	KeyRoleDevice     KeyRole = "device"
	KeyRoleEncryption KeyRole = "encryption"
)

type KeyRecord struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Role          KeyRole   `json:"role"`
	PublicKey     string    `json:"publicKey"`
	AddedAt       time.Time `json:"addedAt"`
	RevokedAt     time.Time `json:"revokedAt,omitempty"`
	RevokedReason string    `json:"revokedReason,omitempty"`
}

type Profile struct {
	DisplayName string            `json:"displayName,omitempty"`
	Bio         string            `json:"bio,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

type MemoryEncryption struct {
	Algorithm          string `json:"algorithm,omitempty"`
	RecipientKeyID     string `json:"recipientKeyId,omitempty"`
	EphemeralPublicKey string `json:"ephemeralPublicKey,omitempty"`
	WrappedKey         string `json:"wrappedKey,omitempty"`
	WrappedKeyNonce    string `json:"wrappedKeyNonce,omitempty"`
	CipherNonce        string `json:"cipherNonce,omitempty"`
}

type MemoryObject struct {
	CID         string            `json:"cid"`
	Type        string            `json:"type"`
	CreatedAt   time.Time         `json:"createdAt"`
	ContentHash string            `json:"contentHash"`
	Payload     string            `json:"payload,omitempty"`
	Ciphertext  string            `json:"ciphertext,omitempty"`
	Encryption  *MemoryEncryption `json:"encryption,omitempty"`
	Visibility  Visibility        `json:"visibility"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Signature   string            `json:"signature,omitempty"`
}

type MemoryManifest struct {
	Version    string     `json:"version"`
	CID        string     `json:"cid"`
	CreatedAt  time.Time  `json:"createdAt"`
	Visibility Visibility `json:"visibility"`
	Items      []string   `json:"items"`
	RootHash   string     `json:"rootHash"`
	Signature  string     `json:"signature,omitempty"`
}

type Attestation struct {
	CID          string                 `json:"cid"`
	Version      string                 `json:"version"`
	IssuerID     string                 `json:"issuerId"`
	IssuerKeyID  string                 `json:"issuerKeyId"`
	SubjectID    string                 `json:"subjectId"`
	ClaimType    string                 `json:"claimType"`
	ClaimPayload map[string]interface{} `json:"claimPayload"`
	IssuedAt     time.Time              `json:"issuedAt"`
	ValidFrom    time.Time              `json:"validFrom"`
	ValidTo      time.Time              `json:"validTo,omitempty"`
	EvidenceRef  string                 `json:"evidenceRef,omitempty"`
	Signature    string                 `json:"signature"`
}

type IdentityEvent struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	IdentityID  string                 `json:"identityId"`
	PrevEventID string                 `json:"prevEventId,omitempty"`
	SignerKeyID string                 `json:"signerKeyId"`
	Timestamp   time.Time              `json:"timestamp"`
	Payload     map[string]interface{} `json:"payload"`
	Signature   string                 `json:"signature"`
}

type IdentityDocument struct {
	ID                string      `json:"id"`
	Version           string      `json:"version"`
	CreatedAt         time.Time   `json:"createdAt"`
	UpdatedAt         time.Time   `json:"updatedAt"`
	RootKeyID         string      `json:"rootKeyId"`
	ActiveKeys        []KeyRecord `json:"activeKeys"`
	Profile           Profile     `json:"profile,omitempty"`
	PublicMemoryRoot  string      `json:"publicMemoryRoot,omitempty"`
	PrivateMemoryRoot string      `json:"privateMemoryRoot,omitempty"`
	AttestationRefs   []string    `json:"attestationRefs,omitempty"`
	LatestEventID     string      `json:"latestEventId,omitempty"`
}

type SignedIdentityState struct {
	Document IdentityDocument `json:"document"`
	Events   []IdentityEvent  `json:"events"`
}

type Challenge struct {
	IdentityID string    `json:"identityId"`
	Nonce      string    `json:"nonce"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type ChallengeResponse struct {
	Challenge   Challenge `json:"challenge"`
	SignerKeyID string    `json:"signerKeyId"`
	Signature   string    `json:"signature"`
}
