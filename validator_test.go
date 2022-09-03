package jwt_validator

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwx "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

const (
	bearer = "Bearer %s"

	issuer           = "javi.secops.com"
	internalAudience = "javi.internal.secops.com"
	externalAudience = "javi.external.secops.com"

	clientIDKey   = "clientId"
	clientIDValue = "value"

	aud = "aud"
	iss = "iss"
)

var (
	scopes  = []string{"test:scope:1", "test:scope:2"}
	secret  = []byte("secret")
	keyFunc = func(*jwt.Token) (interface{}, error) {
		return secret, nil
	}
)

func TestValidateToken(t *testing.T) {
	a := assert.New(t)

	t.Run("Success Internal audience", func(t *testing.T) {
		tok, _ := jwx.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Audience([]string{internalAudience}).
			Claim(clientIDKey, clientIDValue).
			Build()

		signed, _ := jwx.Sign(tok, jwx.WithKey(jwa.HS256, secret))

		validations := Validations{
			NeededScopes:            nil,
			InternalAudienceAllowed: true,
			InternalAudience:        internalAudience,
			ExternalAudienceAllowed: false,
			IssuerRequired:          true,
			Issuer:                  issuer,
		}

		claims, err := ValidateToken(fmt.Sprintf(bearer, string(signed)), keyFunc, validations)

		a.Nil(err)
		a.NotNil(claims)
	})

	t.Run("Success external audience", func(t *testing.T) {
		tok, _ := jwx.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Audience([]string{externalAudience}).
			Claim(clientIDKey, clientIDValue).
			Build()

		signed, _ := jwx.Sign(tok, jwx.WithKey(jwa.HS256, secret))

		validations := Validations{
			NeededScopes:            nil,
			ExternalAudienceAllowed: true,
			ExternalAudience:        externalAudience,
			IssuerRequired:          true,
			Issuer:                  issuer,
		}

		claims, err := ValidateToken(fmt.Sprintf(bearer, string(signed)), keyFunc, validations)

		a.Nil(err)
		a.NotNil(claims)
	})

	t.Run("Fail audience validation", func(t *testing.T) {
		tok, _ := jwx.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Audience([]string{externalAudience}).
			Claim(clientIDKey, clientIDValue).
			Build()

		signed, _ := jwx.Sign(tok, jwx.WithKey(jwa.HS256, secret))

		validations := Validations{
			NeededScopes:            nil,
			ExternalAudienceAllowed: false,
			InternalAudience:        internalAudience,
			InternalAudienceAllowed: true,
			IssuerRequired:          true,
			Issuer:                  issuer,
		}

		claims, err := ValidateToken(fmt.Sprintf(bearer, string(signed)), keyFunc, validations)

		a.NotNil(err)
		a.ErrorIs(err, ErrInvalidClaims)
		a.Nil(claims)
	})

	t.Run("Error parsing token", func(t *testing.T) {
		tok, _ := jwx.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Audience([]string{externalAudience}).
			Claim(clientIDKey, clientIDValue).
			Claim(scope, scopes[0]).
			Build()

		signed, _ := jwx.Sign(tok, jwx.WithKey(jwa.HS256, secret))

		keyFunc := func(*jwt.Token) (interface{}, error) {
			return "not_the_secret", nil
		}

		validations := Validations{
			NeededScopes:            scopes,
			ExternalAudienceAllowed: true,
			ExternalAudience:        externalAudience,
			IssuerRequired:          true,
			Issuer:                  issuer,
		}

		claims, err := ValidateToken(fmt.Sprintf(bearer, string(signed)), keyFunc, validations)

		a.NotNil(err)
		a.ErrorIs(err, ErrParsingToken)
		a.Nil(claims)
	})

	t.Run("Token not valid", func(t *testing.T) {
		tok, _ := jwx.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Expiration(time.Now().Add(time.Second*-2)).
			Audience([]string{externalAudience}).
			Claim(clientIDKey, clientIDValue).
			Build()

		signed, _ := jwx.Sign(tok, jwx.WithKey(jwa.HS256, secret))

		validations := Validations{
			NeededScopes:            nil,
			ExternalAudienceAllowed: true,
			ExternalAudience:        externalAudience,
			IssuerRequired:          true,
			Issuer:                  issuer,
		}

		claims, err := ValidateToken(fmt.Sprintf(bearer, string(signed)), keyFunc, validations)

		a.NotNil(err)
		a.ErrorIs(err, ErrParsingToken)
		a.Nil(claims)
	})
}
