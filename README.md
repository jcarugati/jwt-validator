# JWT Validator

## Quick Start

```go
package main

import validator "github.com/jcarugati/jwt-validator"

const (
	token   = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiamF2aS5pbnRlcm5hbC5zZWNvcHMuY29tIl0sImNsaWVudElkIjoidmFsdWUiLCJpYXQiOjE2NjIyMTg5NjIsImlzcyI6Imphdmkuc2Vjb3BzLmNvbSJ9.bwIFsToppIdjed_kZ9xr_31P57-jdD930PPEG0sVmvI"
	jwksURL = "https://--YOUR DOMAIN----/.well-known/jwks.json"
)

func main() {
	// Create validations
	validations := validator.Validations{
		NeededScopes:            nil,
		InternalAudienceAllowed: true,
		InternalAudience:        internalAudience,
		ExternalAudienceAllowed: false,
		IssuerRequired:          true,
		Issuer:                  issuer,
	}

	// Can configure a jkws URL keyFunc if needed
	keyFunc := validator.MakeKeyFunc(jwksURL, 1000)

	// The validation process returns an error if the token could not be validated
	// In case the token is valid it'll return the claims embedded
	claims, err := validator.ValidateToken(token, keyFunc, validations)
```
