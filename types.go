package main

type TokenRequest struct {
	ApiVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   TokenMetadata `json:"metadata"`
	Spec       TokenSpec     `json:"spec"`
}

type TokenMetadata struct {
	Namespace string `json:"namespace"`
}

type TokenSpec struct {
	Audiences         []string `json:"audiences"`
	ExpirationSeconds uint32   `json:"expirationSeconds"`
}

type TokenResponse struct {
	Status TokenResponseStatus `json:"status"`
}

type TokenResponseStatus struct {
	Token string `json:"token"`
}

type CodeResponse struct {
	IdToken string `json:"id_token"`
}

type JwtPayloadPartial struct {
	Exp int64 `json:"exp"`
}
