package httpserver

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ChandraNarreddy/siv"
	"github.com/ChandraNarreddy/swoossh/storage"
	"github.com/ChandraNarreddy/swoossh/user"
	"github.com/coreos/go-oidc"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/oauth2"
)

type ApiKeyCreds struct {
	ApiKeyID string
	ApiKey   []byte
}

type cookie struct {
	Principal string
	Expiry    int64
	IsAdmin   bool
}

type DefaultAuthnzResult struct {
	authenticatedPrincipal         user.User
	authorizationResult            *bool
	errorAscertainingPrincipal     bool
	errorAscertainingAuthorization bool
	isAdmin                        *bool
}

func (c *DefaultAuthnzResult) AuthenticatedPrincipal() (user.User, error) {
	if c.errorAscertainingPrincipal {
		return nil, fmt.Errorf("Error ascertaining principal")
	}
	if c.authenticatedPrincipal == nil {
		return nil, nil
	}
	return c.authenticatedPrincipal, nil
}
func (c *DefaultAuthnzResult) AuthorizationResult() (*bool, error) {
	if c.errorAscertainingAuthorization {
		return nil, fmt.Errorf("Error ascertaining authorization of caller")
	}
	if c.authorizationResult == nil {
		return nil, nil
	}
	return c.authorizationResult, nil
}

func (c *DefaultAuthnzResult) IsAdmin() *bool {
	return c.isAdmin
}

type DefaultHTTPServerAuthHandler struct {
	AuthzCreds                    []*ApiKeyCreds
	ApiKeySignatureValidityInSecs *int64
	ApiKeyAuthzReqHeader          *string
	OAuthClient                   OAuthClientInterface
	CookieKey                     *string
	Siv                           siv.SIV
	AdminUserClaimsMatches        []string
}

func (c *DefaultHTTPServerAuthHandler) AuthorizationHandler(w http.ResponseWriter, r *http.Request, store storage.Store) (AuthnzResult, bool, error) {

	failedAuthorization := false
	succeededAuthorization := true
	isNotAdmin := false
	isAdmin := true
	erroredAuthzResult := &DefaultAuthnzResult{
		errorAscertainingPrincipal:     true,
		errorAscertainingAuthorization: true,
		isAdmin:                        &isNotAdmin,
	}
	requestPath := r.URL.Path

	// If the request is for oAuth redirect path handler
	if requestPath == c.OAuthClient.GetOauthRedirectPath() {
		client := c.OAuthClient
		stateVal := r.FormValue(client.OAuthStateParamName())
		if stateVal == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("State value is missing in oAuth redirect call"))
			return erroredAuthzResult, true, fmt.Errorf("State value is missing in oAuth redirect call")
		}
		validState, oauthState, stateValidationErr := validateOauthState(stateVal, c.Siv)
		if stateValidationErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(stateValidationErr.Error()))
			return erroredAuthzResult, true, stateValidationErr
		}
		if !validState {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("oAuth State value supplied is not valid"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth State value supplied is not valid")
		}
		code := r.FormValue("code")
		if code == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("oAuth failed"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth Authenticate error: oAuth AuthCode is empty")
		}

		oAuth2Token, oAuth2TokenErr := client.OAuthConfig().Exchange(oauth2.NoContext, code)
		if oAuth2TokenErr != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error obtaining an oAuthToken from authCode"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth Authenticate error: Error obtaining an oAuthToken")
		}

		rawIDToken, ok := oAuth2Token.Extra("id_token").(string)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error obtaining an idToken from oAuthToken"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth Authenticate error: Error obtaining an idToken from oAuthToken")
		}

		verifier := client.GetOpenIDCProvider().Verifier(&oidc.Config{
			ClientID: client.OAuthConfig().ClientID(),
		})

		idToken, verificationErr := verifier.Verify(oauth2.NoContext, rawIDToken)
		if verificationErr != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error verifying the idToken"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth Authenticate error: Error verifying the idToken")
		}

		claims := oAuthClaims{
			EntitlementsField: client.GetEntitlementsFieldForClaims(),
		}
		if err := idToken.Claims(&claims); err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error deserializing the idToken"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth Authenticate error: Error deserializing the idToken")
		}

		if !claims.EmailVerified || claims.Email == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Unverified email address or empty email address in idtoken claims"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth Authenticate error: Unverified email address" +
				" or empty email address in idtoken claims")
		}
		positiveAuthzResult := &DefaultAuthnzResult{}
		baseURL, parseErr := url.Parse(oauthState.BaseURL)
		if parseErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Error parsing the baseURL from the state"))
			return positiveAuthzResult, true, fmt.Errorf("oAuth validation error: Error parsing the baseURL from state parameter")
		}

		cookie := &cookie{
			Principal: claims.Email,
			Expiry:    int64(claims.Expiry),
			IsAdmin:   false,
		}

		if claims.Entitlements != nil {
			for _, role := range c.AdminUserClaimsMatches {
				for _, entitlement := range claims.Entitlements {
					if role == entitlement {
						cookie.IsAdmin = true
						positiveAuthzResult.isAdmin = &isAdmin
						break
					}
				}
			}
		}

		scheme := r.URL.Scheme
		if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
			scheme = forwardedProto
		}

		authCookie, bakeErr := bakeCookie(cookie, c.Siv, *c.CookieKey, scheme)
		if bakeErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Error generating auth cookie - %s", bakeErr.Error())))
			return positiveAuthzResult, true, fmt.Errorf("oAuth Authenticate error: %s", bakeErr.Error())
		}

		http.SetCookie(w, authCookie)
		http.Redirect(w, r, baseURL.String(), http.StatusFound)
		return positiveAuthzResult, true, nil
	}

	authnzResult := &DefaultAuthnzResult{}

	//Checking if the caller is an API Key holder. This takes precedence over any other authnz
	signature := r.Header.Get(*c.ApiKeyAuthzReqHeader)
	if signature != "" {
		valid, keyID, validationErr := c.validateSignature(r)
		if validationErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Signature value is malformed"))
			return erroredAuthzResult, true, fmt.Errorf("Signature value is malformed - %+v", validationErr)
		}
		if !valid {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Signature value is invalid"))
			authnzResult.authorizationResult = &failedAuthorization
			return authnzResult, true, fmt.Errorf("Signature value is invalid")
		}
		log.Printf("Signature valid. Key ID used - %s", *keyID)
		authnzResult.authorizationResult = &succeededAuthorization
		authnzResult.authenticatedPrincipal = nil
		isAdmin := true
		authnzResult.isAdmin = &isAdmin
		return authnzResult, false, nil
	}

	//Now check to see if the caller has a valid cookie
	reqCookie, cookieErr := r.Cookie(*c.CookieKey)
	if cookieErr != nil {
		host := r.Host
		if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
			host = forwardedHost
		}
		scheme := r.URL.Scheme
		if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
			scheme = forwardedProto
		}
		if scheme == "" && r.TLS == nil {
			scheme = "http"
		}
		//Request does not have a cookie, redirecting user to oAuth dance
		c.OAuthClient.SetOauthRedirectURL(host, scheme)
		state, stateGenErr := generateOauthState(r.RequestURI, c.Siv)
		if stateGenErr != nil {
			log.Printf("Error occurred while generating oAuth State - %+v", stateGenErr)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error while generating oAuth state parameter"))
			return erroredAuthzResult, true, fmt.Errorf("oAuth client error: Error while generating oAuth state parameter")
		}
		http.Redirect(w, r, c.OAuthClient.GetAuthCodeURL(state), http.StatusFound)
		return erroredAuthzResult, true, nil
	} else {
		//Request does have a cookie. Validate and extract the principal field
		var readIntoCookie cookie
		expiredCookie, cookieIndulgeErr := indulgeCookie(&readIntoCookie, reqCookie.Value, c.Siv)
		if cookieIndulgeErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("Cookie is malformed - %s", cookieIndulgeErr.Error())))
			return erroredAuthzResult, true, fmt.Errorf("Error while decoding the cookie value - %s", cookieIndulgeErr)
		}
		if *expiredCookie {
			deleteCookie := &http.Cookie{
				Name:   *c.CookieKey,
				MaxAge: -1,
				Path:   "/",
			}
			http.SetCookie(w, deleteCookie)
			http.Redirect(w, r, r.URL.String(), http.StatusTemporaryRedirect)
			return erroredAuthzResult, true, fmt.Errorf("Cookie value expired")
		}

		caller := readIntoCookie.Principal
		callerExists, user, existsCheckFailure := c.checkCallerExists(caller, store)
		if existsCheckFailure != nil {
			log.Printf("Failure while checking for user %s existence", caller)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Failure while checking for user's existence"))
			return erroredAuthzResult, true, fmt.Errorf("Failure while checking for user %s existence", caller)
		}

		if !*callerExists {
			log.Printf("User %s does not exist", caller)
			authnzResult.authorizationResult = &failedAuthorization
			authnzResult.authenticatedPrincipal = nil
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("User %s does not exist", caller)))
			return authnzResult, true, fmt.Errorf("User %s does not exist", caller)
		}

		isAdmin := readIntoCookie.IsAdmin
		if isAdmin {
			log.Printf("Caller %s is admin, letting through without further ado", caller)
			authnzResult.authorizationResult = &succeededAuthorization
			authnzResult.authenticatedPrincipal = user
			authnzResult.isAdmin = &isAdmin
			return authnzResult, false, nil
		}

		authorizedCaller, authorizationErr := c.authorizeCaller(r, caller)
		if authorizationErr != nil {
			log.Printf("Errored out while validating authorization of caller %s for resource requested", caller)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Caller's authorization could not be ascertained"))
			return erroredAuthzResult, true, fmt.Errorf("Errored out while validating caller %s for resource requested", caller)
		}
		authnzResult.authorizationResult = authorizedCaller
		authnzResult.authenticatedPrincipal = user
		authnzResult.isAdmin = &isNotAdmin
		return authnzResult, false, nil
	}
}

func (c *DefaultHTTPServerAuthHandler) authorizeCaller(r *http.Request, caller string) (*bool, error) {
	return nil, nil
}

func (c *DefaultHTTPServerAuthHandler) checkCallerExists(email string, store storage.Store) (*bool, user.User, error) {
	var userFound bool
	userEmailFilter := &storage.DefaultStoreUserFilter{
		EmailAddrProjection: &email,
	}
	user, getUserErr := store.GetUser(userEmailFilter)
	if getUserErr != nil {
		log.Printf("Error while retrieving user with the caller filter %+v - %+v", userEmailFilter, getUserErr)
		return nil, nil, fmt.Errorf("Error while retrieving user with the caller filter %+v - %+v", userEmailFilter, getUserErr)
	}
	if user == nil {
		log.Printf("No user found for the filter %+v", userEmailFilter)
		userFound = false
		return &userFound, nil, nil
	}
	userFound = true
	return &userFound, user, nil
}

func (c *DefaultHTTPServerAuthHandler) validateSignature(r *http.Request) (bool, *string, error) {
	auth := r.Header.Get(*c.ApiKeyAuthzReqHeader)
	if auth != "" {
		if strings.HasPrefix(auth, APIAuthHeaderVer1Prefix) {
			authSansVersion := strings.TrimPrefix(auth, APIAuthHeaderVer1Prefix)
			valid, principalID, validationErr := ValidateSignature_v1(r, c.AuthzCreds, authSansVersion, time.Now(), *c.ApiKeySignatureValidityInSecs)
			if validationErr != nil {
				log.Print("Signature validation errored out")
				return false, nil, fmt.Errorf("Signature validation errored out")
			}
			return valid, principalID, nil
		} else {
			log.Printf("Unsupported signature version or no version specified")
			return false, nil, fmt.Errorf("Unsupported signature version or no version specified")
		}
	} else {
		log.Printf("Signature header is missing or its value is empty")
		return false, nil, fmt.Errorf("Signature header is missing or its value is empty")
	}
}

func generateOauthState(baseURL string, siv siv.SIV) (string, error) {
	oauthState := &oAuthState{
		Expiry:  time.Now().Add(10 * time.Minute).Unix(),
		BaseURL: baseURL,
	}
	b, marshalErr := msgpack.Marshal(oauthState)
	if marshalErr != nil {
		return "", fmt.Errorf("oAuth client error: Error while generating oAuth state parameter")
	}
	encryptedState, encryptionErr := siv.Wrap(b)
	if encryptionErr != nil {
		return "", fmt.Errorf("oAuth Client error: Error while encrypting oAuth state parameter")
	}
	encodedState := base64.RawURLEncoding.EncodeToString(encryptedState)
	return encodedState, nil
}

func validateOauthState(state string, siv siv.SIV) (bool, *oAuthState, error) {
	oauthStateEncrypted, decodeErr := base64.RawURLEncoding.DecodeString(state)
	if decodeErr != nil {
		return false, nil, fmt.Errorf("oAuth validation failure: State value could not be decoded")
	}
	plainStateValueBytes, failure := siv.Unwrap(oauthStateEncrypted)
	if failure != nil {
		return false, nil, fmt.Errorf("oAuth validation error: State value could not be decrypted")
	}
	var oauthState oAuthState
	if unMarshallErr := msgpack.Unmarshal(plainStateValueBytes,
		&oauthState); unMarshallErr != nil {
		return false, nil, fmt.Errorf("oAuth validation error: State value could not be deserialized")
	}
	if time.Now().Unix() > oauthState.Expiry {
		return false, nil, nil
	}
	return true, &oauthState, nil
}

func bakeCookie(k *cookie, siv siv.SIV, cookieKey string, scheme string) (*http.Cookie, error) {
	b, wrapErr := msgpack.Marshal(k)
	if wrapErr != nil {
		return nil, fmt.Errorf("Error marshalling auth cookie")
	}
	wrappedUpCookie, encryptionErr := siv.Wrap(b)
	if encryptionErr != nil {
		return nil, fmt.Errorf("Error encrypting auth cookie")
	}
	authCookie := &http.Cookie{
		Name:     cookieKey,
		Value:    base64.StdEncoding.EncodeToString(wrappedUpCookie),
		HttpOnly: true,
		Path:     "/",
	}
	if scheme == "https" {
		authCookie.Secure = true
	}
	return authCookie, nil
}

func indulgeCookie(k *cookie, cookieVal string, siv siv.SIV) (*bool, error) {
	expiredCookie := false
	encryptedCookie, decodeErr := base64.StdEncoding.DecodeString(cookieVal)
	if decodeErr != nil {
		return nil, fmt.Errorf("Error while decoding the cookie value - Cookie is malformed")
	}
	plainBytes, failure := siv.Unwrap(encryptedCookie)
	if failure != nil {
		return nil, fmt.Errorf("Error while decrypting the cookie value")
	}
	unMarshallErr := msgpack.Unmarshal(plainBytes, k)
	if unMarshallErr != nil {
		return nil, fmt.Errorf("Error while unmarshalling the cookie value")
	}
	if time.Now().Unix() > k.Expiry {
		expiredCookie = true
		return &expiredCookie, nil
	}
	return &expiredCookie, nil
}
