package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/example/decentid/internal/app"
	"github.com/example/decentid/pkg/types"
)

func (s *Server) apiSummary(w http.ResponseWriter, r *http.Request) {
	if !s.requireGET(w, r) {
		return
	}
	summary, err := s.service.Summary()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "summary_failed", err)
		return
	}
	s.writeOK(w, summary)
}

func (s *Server) apiCreateIdentity(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req createIdentityRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.CreateIdentity(req.DisplayName, req.OutPath, false)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "create_identity_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiPublicState(w http.ResponseWriter, r *http.Request) {
	if !s.requireGET(w, r) {
		return
	}
	result, err := s.service.PublicState()
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "public_state_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiExportState(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req exportStateRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.ExportState(req.OutPath)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "export_state_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiAddMemory(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req addMemoryRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.AddMemory(req.Type, req.Payload, types.Visibility(req.Visibility))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "add_memory_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiShowMemory(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req showMemoryRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.ShowMemory(req.MemoryFile)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "show_memory_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiAddDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req addDeviceRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.AddDevice(req.Label)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "add_device_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req revokeDeviceRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.RevokeDevice(req.KeyID, req.Reason)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "revoke_device_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiRotateRoot(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req rotateRootRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.RotateRoot(req.Label)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "rotate_root_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiCreateChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req createChallengeRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	ttl, err := parseDuration(req.TTL, 5*time.Minute)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_ttl", err)
		return
	}
	result, err := s.service.CreateChallenge(req.IdentityID, ttl)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "challenge_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiRespondChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req respondChallengeRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	challenge, err := app.ParseChallenge(req.ChallengeJSON)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_challenge", err)
		return
	}
	result, err := s.service.RespondToChallenge(challenge, req.SignerKeyID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "respond_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiVerifyChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req verifyChallengeRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	state, err := app.ParseSignedState(req.StateJSON)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_state", err)
		return
	}
	response, err := app.ParseChallengeResponse(req.ResponseJSON)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_response", err)
		return
	}
	s.writeOK(w, app.VerifyChallengeResponse(state, response))
}

func (s *Server) apiIssueAttestation(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req issueAttestationRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	validFor, err := parseDuration(req.ValidFor, 24*time.Hour)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_valid_for", err)
		return
	}
	result, err := s.service.IssueAttestation(req.SubjectID, req.ClaimType, req.ClaimValue, req.Evidence, validFor, req.OutPath)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "issue_attestation_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiVerifyAttestation(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req verifyAttestationRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	state, err := app.ParseSignedState(req.IssuerStateJSON)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_issuer_state", err)
		return
	}
	att, err := app.ParseAttestation(req.AttestationJSON)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_attestation", err)
		return
	}
	s.writeOK(w, app.VerifyAttestationWithState(state, att))
}

func (s *Server) apiAttachAttestation(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req attachAttestationRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	att, err := app.ParseAttestation(req.AttestationJSON)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_attestation", err)
		return
	}
	result, err := s.service.AttachAttestation(att)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "attach_attestation_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiPublish(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req publishRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	wait, err := parseDuration(req.Wait, 30*time.Second)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_wait", err)
		return
	}
	result, err := s.service.StartPublish(req.ListenAddr, wait, req.IncludeAttestations)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "publish_failed", err)
		return
	}
	s.writeOK(w, result)
}

func (s *Server) apiResolve(w http.ResponseWriter, r *http.Request) {
	if !s.requirePOST(w, r) {
		return
	}
	var req resolveRequest
	if err := s.readJSON(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.service.ResolveState(req.PeerAddr, req.IdentityID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "resolve_failed", err)
		return
	}
	s.writeOK(w, result)
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, errors.New("duration must be positive")
	}
	return duration, nil
}
