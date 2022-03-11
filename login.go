package globalsign

import (
	"net/http"
)

// LoginRequest .
type LoginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// LoginResponse .
type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

// LoginService .
type LoginService interface {
	Login(*LoginRequest) (*LoginResponse, *Response, error)
}

type loginService struct {
	client *Client
}

func (s *loginService) Login(req *LoginRequest) (*LoginResponse, error) {
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
