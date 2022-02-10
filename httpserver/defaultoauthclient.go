package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type oAuthClaims struct {
	Email             string  `json:"email"`
	EmailVerified     bool    `json:"email_verified"`
	Expiry            float64 `json:"exp"`
	Entitlements      []string
	EntitlementsField string
}

type oAuthState struct {
	Expiry  int64
	BaseURL string
}

type OauthConfig struct {
	*oauth2.Config
}

func (c *OauthConfig) ClientID() string {
	return c.Config.ClientID
}

func (c *OauthConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (OauthTokenInterface, error) {
	return c.Config.Exchange(ctx, code, opts...)
}

type IDTokenVerifier struct {
	*oidc.IDTokenVerifier
}

func (c *IDTokenVerifier) Verify(ctx context.Context, rawIDToken string) (IDTokenInterface, error) {
	return c.IDTokenVerifier.Verify(ctx, rawIDToken)
}

type OIDCProvider struct {
	*oidc.Provider
}

func (c *OIDCProvider) Verifier(config *oidc.Config) IDTokenVerifierInterface {
	idTokenVerifier := c.Provider.Verifier(config)
	tokenVerifier := IDTokenVerifier{idTokenVerifier}
	return &tokenVerifier
}

type OauthClient struct {
	OauthConfig                OauthConfig
	OpenIDCProvider            OIDCProvider
	OauthCallBackHandlerPath   *string
	OauthStateParamName        *string
	EntitlementsFieldForClaims *string
}

func (c *OauthClient) SetOauthRedirectURL(baseHost, scheme string) {
	redirectURL := url.URL{
		Scheme: scheme,
		Host:   baseHost,
	}
	redirectURL.Path = *c.OauthCallBackHandlerPath
	c.OauthConfig.RedirectURL = redirectURL.String()
}

func (c *OauthClient) GetOauthRedirectPath() string {
	redirectURL, _ := url.Parse(c.OauthConfig.RedirectURL)
	return redirectURL.Path
}

func (c *OauthClient) GetAuthCodeURL(state string) string {
	return c.OauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (c *OauthClient) OAuthStateParamName() string {
	return *c.OauthStateParamName
}

func (c *OauthClient) OAuthConfig() OauthConfigInterface {
	return &c.OauthConfig
}

func (c *OauthClient) GetOpenIDCProvider() OIDCProviderInterface {
	return &c.OpenIDCProvider
}

func (c *OauthClient) GetEntitlementsFieldForClaims() string {
	return *c.EntitlementsFieldForClaims
}

func (c *oAuthClaims) UnmarshalJSON(b []byte) error {
	var tmp map[string]interface{}
	err := json.Unmarshal(b, &tmp)
	if err != nil {
		log.Print("Could not unmarshal the token to a map")
		return fmt.Errorf("Could not unmarshal the token to a map")
	}
	if c.EntitlementsField == "" {
		log.Print("Entitlements Field is empty for oAuthClaims. Cannot fetch entitlements if any even present in the token")
	} else {
		if val, ok := tmp[c.EntitlementsField]; !ok {
			log.Print("Entitlements not found in the token")
		} else {
			switch t := val.(type) {
			case string:
				c.Entitlements = []string{t}
			case []string:
				c.Entitlements = t
			default:
				log.Printf("Entitlements field value %+v is neither a string nor a string slice", t)
			}
		}
	}
	if val, ok := tmp["email"]; ok {
		if email, ok := val.(string); !ok {
			log.Printf("email field of claims is of unrecognized type %+v", val)
		} else {
			c.Email = email
		}
	} else {
		log.Print("email not supplied in claims")
	}
	if val, ok := tmp["email_verified"]; ok {
		if emailVerified, ok := val.(bool); !ok {
			log.Printf("email_verified field of claims is of unrecognized type %+v", val)
		} else {
			c.EmailVerified = emailVerified
		}
	} else {
		log.Print("email_verifiied not supplied in claims")
	}
	if val, ok := tmp["exp"]; ok {
		if expiry, ok := val.(float64); !ok {
			log.Printf("expiry field of claims is of unrecognized type %+v", val)
		} else {
			c.Expiry = expiry
		}
	} else {
		log.Print("expiry not supplied in claims")
	}
	return nil
}
