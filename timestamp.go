package globalsign

// TimestampRequest .
type TimestampRequest struct {
	Digest string `json:"digest"`
}

// TimestampResponse .
type TimestampResponse struct {
	Token string `json:"token"`
}
