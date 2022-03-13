package globalsign

// IdentityRequest .
type IdentityRequest struct {
	SubjectDn SubjectDn `json:"subject_dn"`
}

type SubjectDn struct {
	Country                                        string                    `json:"country,omitempty"`
	State                                          string                    `json:"state,omitempty"`
	Locality                                       string                    `json:"locality,omitempty"`
	StreetAddress                                  string                    `json:"street_address,omitempty"`
	Organization                                   string                    `json:"organization,omitempty"`
	OrganizationUnit                               []string                  `json:"organization_unit,omitempty"`
	CommonName                                     string                    `json:"common_name,omitempty"`
	Email                                          string                    `json:"email,omitempty"`
	JurisdictionOfIncorporationLocalityName        string                    `json:"jurisdiction_of_incorporation_locality_name,omitempty"`
	JurisdictionOfIncorporationStateOrProvinceName string                    `json:"jurisdiction_of_incorporation_state_or_province_name,omitempty"`
	JurisdictionOfIncorporationCountryName         string                    `json:"jurisdiction_of_incorporation_country_name,omitempty"`
	BusinessCategory                               string                    `json:"business_category,omitempty"`
	ExtraAttributes                                []SubjectDnExtraAttribute `json:"extra_attributes,omitempty"`
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
