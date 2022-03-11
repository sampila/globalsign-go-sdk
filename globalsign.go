package globalsign

import (
	"errors"
	"net/http"
)

const (
	defaultBaseURL = "https://emea.api.dss.globalsign.com:8443"
	baseAPI        = "/v2"
	contentType    = "application/json;charset=utf-8"
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
