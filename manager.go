package globalsign

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	authTokenTTL = 30 * time.Minute
	identityTTL  = 10 * time.Minute
)

// ManagerOption .
type ManagerOption struct {
	BaseURL         string
	APIKey          string
	APISecret       string
	CertificatePath string
	PrivateKeyPath  string
}

// Valid determine whether option is valid
func (o *ManagerOption) Valid() bool {
	return o.APIKey != "" && o.APISecret != "" && o.CertificatePath != "" && o.PrivateKeyPath != ""
}

// Manager .
type Manager struct {
	sync.RWMutex

	apiKey    string
	apiSecret string

	token   string
	tokenTs time.Time

	client *Client
	vault  *IdentityVault
}

// NewManager is a wrapper for client and
func NewManager(option *ManagerOption) (*Manager, error) {
	if !option.Valid() {
		return nil, errors.New("option not valid")
	}

	baseURL := defaultBaseURL
	if option.BaseURL != "" {
		baseURL = option.BaseURL
	}

	baseURLAPI, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	co := &ClientOptions{
		BaseURL:      baseURLAPI,
		ApiKey:       option.APIKey,
		ApiSecret:    option.APIKey,
		CertFilePath: option.CertificatePath,
		KeyFilePath:  option.PrivateKeyPath,
	}

	client, err := NewClientWithOpts(co)
	if err != nil {
		return nil, err
	}

	return &Manager{
		apiKey:    option.APIKey,
		apiSecret: option.APISecret,
		client:    client,
		vault:     NewIdentityVault(identityTTL),
	}, nil
}

// GetIdentity .
func (s *Manager) GetIdentity(ctx context.Context, signer string, req *IdentityRequest) (*DSSIdentity, error) {
	// Check identity in vault.
	identity, ok := s.vault.Get(signer)
	if ok {
		return identity, nil
	}

	// Otherwise request new identity,
	err := s.ensureToken(ctx)
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
	s.vault.Set(signer, identity)

	return identity, nil
}

// Sign .
func (s *Manager) Sign(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	err := s.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	identity, err := s.GetIdentity(ctx, signer, identityReq)
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
func (s *Manager) Timestamp(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	err := s.ensureToken(ctx)
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

// ensureToken automatically request new token if token expired.
func (s *Manager) ensureToken(ctx context.Context) error {
	s.RLock()
	token := s.token
	tokenTs := s.tokenTs
	s.RUnlock()

	// if token not yet acquired or expired
	if token == "" || time.Since(tokenTs) > authTokenTTL {
		resp, err := s.client.DSSService.Login(&LoginRequest{
			APIKey:    s.apiKey,
			APISecret: s.apiSecret,
		})
		if err != nil {
			return err
		}

		s.Lock()
		s.token = resp.AccessToken
		s.tokenTs = time.Now()
		s.client.SetAuthToken(s.token)
		s.Unlock()
	}

	return nil
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
