package web

import (
	"html/template"
	"time"

	"github.com/example/decentid/internal/app"
)

type PageData struct {
	Title        string
	Active       string
	Summary      app.LocalSummary
	IdentityPath string
	Now          time.Time
}

type APIResponse struct {
	OK     bool        `json:"ok"`
	Data   interface{} `json:"data,omitempty"`
	Error  *APIError   `json:"error,omitempty"`
	HTML   string      `json:"html,omitempty"`
	Target string      `json:"target,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type createIdentityRequest struct {
	DisplayName string `json:"displayName"`
	OutPath     string `json:"outPath"`
}

type exportStateRequest struct {
	OutPath string `json:"outPath"`
}

type addMemoryRequest struct {
	Type       string `json:"type"`
	Payload    string `json:"payload"`
	Visibility string `json:"visibility"`
}

type showMemoryRequest struct {
	MemoryFile string `json:"memoryFile"`
}

type addDeviceRequest struct {
	Label string `json:"label"`
}

type revokeDeviceRequest struct {
	KeyID  string `json:"keyId"`
	Reason string `json:"reason"`
}

type rotateRootRequest struct {
	Label string `json:"label"`
}

type createChallengeRequest struct {
	IdentityID string `json:"identityId"`
	TTL        string `json:"ttl"`
}

type respondChallengeRequest struct {
	ChallengeJSON string `json:"challengeJson"`
	SignerKeyID   string `json:"signerKeyId"`
}

type verifyChallengeRequest struct {
	StateJSON    string `json:"stateJson"`
	ResponseJSON string `json:"responseJson"`
}

type issueAttestationRequest struct {
	SubjectID  string `json:"subjectId"`
	ClaimType  string `json:"claimType"`
	ClaimValue string `json:"claimValue"`
	Evidence   string `json:"evidenceRef"`
	ValidFor   string `json:"validFor"`
	OutPath    string `json:"outPath"`
}

type verifyAttestationRequest struct {
	IssuerStateJSON string `json:"issuerStateJson"`
	AttestationJSON string `json:"attestationJson"`
}

type attachAttestationRequest struct {
	AttestationJSON string `json:"attestationJson"`
}

type publishRequest struct {
	ListenAddr          string `json:"listenAddr"`
	Wait                string `json:"wait"`
	IncludeAttestations bool   `json:"includeAttestations"`
}

type resolveRequest struct {
	PeerAddr   string `json:"peerAddr"`
	IdentityID string `json:"identityId"`
}

type templateFuncs struct{}

func (templateFuncs) Safe(s string) template.HTML {
	return template.HTML(s)
}
