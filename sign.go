package globalsign

// SigningRequest .
type SigningRequest struct {
	ID string `json:"id"`

	// a hex encoded sha256 checksum for source file
	Digest string `json:"digest"`
}

// SigningResponse .
type SigningResponse struct {
	Signature string `json:"signature"`
}
