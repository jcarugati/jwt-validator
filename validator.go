package jwt_validator

import (
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

const (
	scope = "scope"
)

type Validations struct {
	Issuer                  string
	IssuerRequired          bool
	NeededScopes            []string
	InternalAudienceAllowed bool
	InternalAudience        string
	ExternalAudienceAllowed bool
	ExternalAudience        string
}

var (
	ErrParsingToken    = errors.New("error parsing token")
	ErrInvalidToken    = errors.New("parsed token is invalid")
	ErrInvalidClaims   = errors.New("invalid claims")
	ErrInvalidIssuer   = errors.New("invalid issuer")
	ErrInvalidAudience = errors.New("invalid audience")
	ErrInvalidScopes   = errors.New("invalid scopes")
)

func ValidateToken(fulltoken string, keyfunc jwt.Keyfunc, validations Validations) (map[string]any, error) {

	jwtToken := strings.Split(fulltoken, " ")[1]

	parsedToken, err := jwt.Parse(jwtToken, keyfunc)
	if err != nil {
		return nil, errors.Wrap(ErrParsingToken, err.Error())
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid || claims.Valid() != nil {
		return nil, ErrInvalidToken
	}

	if err := validClaims(claims, validations); err != nil {
		return claims, errors.Wrap(ErrInvalidClaims, err.Error())
	}

	return claims, nil
}

func validClaims(claims jwt.MapClaims, validations Validations) error {
	if !claims.VerifyIssuer(validations.Issuer, validations.IssuerRequired) {
		return ErrInvalidIssuer
	}

	if !validAudience(claims, validations) {
		return ErrInvalidAudience
	}

	if !validScopes(fmt.Sprint((claims)[scope]), validations.NeededScopes) {
		return ErrInvalidScopes
	}

	return nil
}

func validAudience(claims jwt.MapClaims, validations Validations) bool {
	var validInternalAudience bool
	var validExternalAudience bool
	if validations.ExternalAudienceAllowed {
		validExternalAudience = claims.VerifyAudience(validations.ExternalAudience, validations.ExternalAudienceAllowed)
	}
	if validations.InternalAudienceAllowed {
		validInternalAudience = claims.VerifyAudience(validations.InternalAudience, validations.InternalAudienceAllowed)
	}
	return validInternalAudience || validExternalAudience
}

func validScopes(scope string, neededScopes []string) bool {
	for _, neededScope := range neededScopes {
		if !strings.Contains(scope, neededScope) {
			return false
		}
	}
	return true
}

func MakeKeyFunc(jwksURL string, refreshInterval int64) (jwt.Keyfunc, error) {
	options := keyfunc.Options{
		RefreshInterval: time.Duration(refreshInterval) * time.Second,
		RefreshErrorHandler: func(err error) {
			fmt.Println("Error refreshing jwks", err)
		},
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		fmt.Println("Failed to create JWKS from resource at the given URL", err)
		return nil, err
	}

	return jwks.Keyfunc, nil
}
