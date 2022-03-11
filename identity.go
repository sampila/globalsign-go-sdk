package globalsign

// IdentityRequest .
type IdentityRequest struct {
	SubjectDn SubjectDn `json:"subject_dn"`
}

type SubjectDn struct {
	Country                                        string                    `json:"country"`
	State                                          string                    `json:"state"`
	Locality                                       string                    `json:"locality"`
	StreetAddress                                  string                    `json:"street_address"`
	Organization                                   string                    `json:"organization"`
	OrganizationUnit                               []string                  `json:"organization_unit"`
	CommonName                                     string                    `json:"common_name"`
	Email                                          string                    `json:"email"`
	JurisdictionOfIncorporationLocalityName        string                    `json:"jurisdiction_of_incorporation_locality_name"`
	JurisdictionOfIncorporationStateOrProvinceName string                    `json:"jurisdiction_of_incorporation_state_or_province_name"`
	JurisdictionOfIncorporationCountryName         string                    `json:"jurisdiction_of_incorporation_country_name"`
	BusinessCategory                               string                    `json:"business_category"`
	ExtraAttributes                                []SubjectDnExtraAttribute `json:"extra_attributes"`
}

type SubjectDnExtraAttribute struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// IdentityResponse .
type IdentityResponse struct {
	ID           string `json:"id"`
	SigningCert  string `json:"signing_cert"`
	OCSPResponse string `json:"ocsp_response"`
}
