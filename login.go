package globalsign

// LoginRequest .
type LoginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// LoginResponse .
type LoginResponse struct {
	AccessToken string `json:"access_token"`
}
