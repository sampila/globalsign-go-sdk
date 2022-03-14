package globalsign

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://emea.api.dss.globalsign.com:8443"
	baseAPI        = "/v2"
	contentType    = "application/json;charset=utf-8"

	// Default authentication token time to live.
	authTokenTTL = 30 * time.Minute

	// Default identity time to live.
	identityTTL = 10 * time.Minute
)

// Errors definition.
var (
	ErrDigestRequired = errors.New("file digest required")
)

// DSSService .
type DSSService interface {
	Login(*LoginRequest) (*LoginResponse, error)
	Identity(*IdentityRequest) (*IdentityResponse, error)
	Timestamp(*TimestampRequest) (*TimestampResponse, error)
	Sign(*SigningRequest) (*SigningResponse, error)
	CertificatePath() (*CertificatePathResponse, error)
	TrustChain() (*TrustChainResponse, error)
	// DSS Identity and sign process.
	DSSGetIdentity(context.Context, string, *IdentityRequest) (*DSSIdentity, error)
	DSSIdentitySign(context.Context, string, *IdentityRequest, []byte) ([]byte, error)
	DSSIdentityTimestamp(context.Context, string, *IdentityRequest, []byte) ([]byte, error)
}

type globalSignDSSService struct {
	client *Client
}

func (s *globalSignDSSService) Login(req *LoginRequest) (*LoginResponse, error) {
	// ensure params not nil
	if req == nil {
		req = &LoginRequest{}
	}

	path := baseAPI + "/login"
	r, err := s.client.NewRequest(http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	result := new(LoginResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *globalSignDSSService) Identity(req *IdentityRequest) (*IdentityResponse, error) {
	path := baseAPI + "/identity"
	r, err := s.client.NewRequest(http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	result := new(IdentityResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *globalSignDSSService) Timestamp(req *TimestampRequest) (*TimestampResponse, error) {
	if req == nil {
		return nil, ErrDigestRequired
	}

	path := baseAPI + "/timestamp/" + req.Digest
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(TimestampResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *globalSignDSSService) Sign(req *SigningRequest) (*SigningResponse, error) {
	if req == nil {
		return nil, ErrDigestRequired
	}

	path := baseAPI + "/identity/" + req.ID + "/sign/" + req.Digest
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(SigningResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *globalSignDSSService) CertificatePath() (*CertificatePathResponse, error) {
	path := baseAPI + "/certificate_path"
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(CertificatePathResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *globalSignDSSService) TrustChain() (*TrustChainResponse, error) {
	path := baseAPI + "/certificate_path"
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(TrustChainResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DSSIdentity represent acquired credential
// from login and identity request.
type DSSIdentity struct {
	// Identity.
	ID string

	// SigningCert.
	SigningCert string

	// OCSP.
	OCSP string

	//CA Certificate.
	CA string

	// Ts timestamp.
	Ts time.Time
}

// GetIdentity .
func (s *globalSignDSSService) DSSGetIdentity(ctx context.Context, signer string, req *IdentityRequest) (*DSSIdentity, error) {
	// Check identity in vault.
	identity, ok := s.client.vault.Get(signer)
	if ok {
		return identity, nil
	}

	// Otherwise request new identity,
	err := s.client.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	// Request id and signing certificate.
	identityResp, err := s.client.DSSService.Identity(req)
	if err != nil {
		return nil, err
	}

	// Request cs certificate.
	certResp, err := s.client.DSSService.CertificatePath()
	if err != nil {
		return nil, err
	}

	identity = &DSSIdentity{
		ID:          identityResp.ID,
		SigningCert: identityResp.SigningCert,
		OCSP:        identityResp.OCSPResponse,
		CA:          certResp.CA,
	}
	s.client.vault.Set(signer, identity)

	return identity, nil
}

// Sign .
func (s *globalSignDSSService) DSSIdentitySign(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	err := s.client.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	identity, err := s.DSSGetIdentity(ctx, signer, identityReq)
	if err != nil {
		return nil, err
	}

	// Encode digest to hex.
	digestHex := strings.ToUpper(hex.EncodeToString(digest))
	signatureResp, err := s.client.DSSService.Sign(&SigningRequest{
		ID:     identity.ID,
		Digest: digestHex,
	})
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(signatureResp.Signature)
}

// Timestamp .
func (s *globalSignDSSService) DSSIdentityTimestamp(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	err := s.client.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	// Encode digest to hex.
	digestHex := strings.ToUpper(hex.EncodeToString(digest))
	timestampResp, err := s.client.DSSService.Timestamp(&TimestampRequest{
		Digest: digestHex,
	})
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(timestampResp.Token)
}
