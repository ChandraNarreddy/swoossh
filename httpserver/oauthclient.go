package httpserver

import (
	"context"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OAuthClientInterface interface {
	SetOauthRedirectURL(baseHost, scheme string)
	GetOauthRedirectPath() string
	GetAuthCodeURL(state string) string
	OAuthStateParamName() string
	//OAuthConfig() *oauth2.Config
	OAuthConfig() OauthConfigInterface
	//GetOpenIDCProvider() *oidc.Provider
	GetOpenIDCProvider() OIDCProviderInterface
	GetEntitlementsFieldForClaims() string
}

type OauthTokenInterface interface {
	Extra(key string) interface{}
}

type OauthConfigInterface interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (OauthTokenInterface, error)
	ClientID() string
}

type OIDCProviderInterface interface {
	Verifier(config *oidc.Config) IDTokenVerifierInterface
}

type IDTokenVerifierInterface interface {
	Verify(ctx context.Context, rawIDToken string) (IDTokenInterface, error)
}

type IDTokenInterface interface {
	Claims(v interface{}) error
}
