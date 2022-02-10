package httpserver

import (
	"crypto/rand"
	"embed"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ChandraNarreddy/siv"
)

//go:embed test_templates
var templates embed.FS

func TestDefaultHTTPServerHomeHandler(t *testing.T) {
	//DefaultHTTPServerHomeHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	putUser(t)
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:             ddbStore,
		CA:                &mockCA{},
		AuthHandler:       &affirmativeNonAdminAuthHandler{principal: "smith", uuid: "some-uuid"},
		TemplateFS:        templates,
		AdminHomeTmplName: strPtr("test_templates/admin_home.tmpl"),
		HomeTmplName:      strPtr("test_templates/home.tmpl"),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/swoossh/home", nil)
	DefaultHTTPServerHomeHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("home handler responded with non-200 response for valid request")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	if strings.Contains(string(bodyBytes), "Admin") {
		t.Errorf("home handler responded with admin home page for non-admin caller")
	}

	genericDefaultHTTPServer = &DefaultHTTPServer{
		Store:             ddbStore,
		CA:                &mockCA{},
		AuthHandler:       &affirmativeAdminAuthHandler{principal: "smith", uuid: "some-uuid", customAuthnzResult: true},
		TemplateFS:        templates,
		AdminHomeTmplName: strPtr("test_templates/admin_home.tmpl"),
		HomeTmplName:      strPtr("test_templates/home.tmpl"),
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/home", nil)
	DefaultHTTPServerHomeHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("home handler responded with non-200 response for valid request")
	}
	bodyBytes, _ = io.ReadAll(w.Result().Body)
	if !strings.Contains(string(bodyBytes), "Admin") {
		t.Errorf("home handler responded with non-admin home page for non-admin caller")
	}
}

func TestDefaultHTTPPasswdChangeHandler(t *testing.T) {
	//DefaultHTTPPasswdChangeHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	putUser(t)

	cookieSecret := make([]byte, 32)
	_, err := rand.Read(cookieSecret)
	if err != nil {
		log.Fatalf("Could not generate random string for cookie secret - %+v", err)
	}
	keypair, aesSIVErr := siv.NewAesSIVBlockPair(cookieSecret)
	if aesSIVErr != nil {
		log.Fatalf("Could not initialize SIV block pair using cookie secret - %+v", aesSIVErr)
	}
	siv, sivErr := siv.NewSIV(keypair)
	if sivErr != nil {
		log.Fatalf("Could not initialize SIV for cookie encryption - %+v", sivErr)
	}
	genericAuthHandler := DefaultHTTPServerAuthHandler{
		AuthzCreds: []*ApiKeyCreds{
			&ApiKeyCreds{
				ApiKeyID: "keyID_1",
				ApiKey:   []byte("some_random_key"),
			},
		},
		ApiKeySignatureValidityInSecs: int64Ptr(int64(300)),
		ApiKeyAuthzReqHeader:          strPtr("Authorization"),
		CookieKey:                     strPtr("test_cookie"),
		Siv:                           siv,
		AdminUserClaimsMatches:        []string{""},
		OAuthClient: &mockOauthClient{
			oidcProvider: &mockOIDCProvider{
				verifier: &mockOIDCVerifier{
					token: &mockOIDCToken{},
				},
			},
		},
	}
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &genericAuthHandler,
	}
	goodCookie := &cookie{
		Principal: "email@email.com",
		Expiry:    time.Now().Add(10 * time.Minute).Unix(),
		IsAdmin:   false,
	}
	goodBakedCookie, _ := bakeCookie(goodCookie, siv, "test_cookie", "https")

	validPasswdChangeInput := `{
    "currentPassword":"$1",
    "newPassword":"$2"
  }`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/swoossh/changePasswd", strings.NewReader(validPasswdChangeInput))
	r.AddCookie(goodBakedCookie)
	DefaultHTTPPasswdChangeHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("passwd change handler responded with non-200 response for valid request")
	}

	genericAdminDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/smith", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericAdminDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by Name handler responded with non-200 response for previously passwd changed user")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	latestPasswdHash := bodyJSON["data"]["latestPasswdHash"].(string)
	if latestPasswdHash != "$2" {
		t.Errorf("latestPasswdHash returned after update does not match up to expected value")
	}

	emptyPasswdChangeInput := `{
    "currentPassword":"",
    "newPassword":""
  }`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/swoossh/changePasswd", strings.NewReader(emptyPasswdChangeInput))
	r.AddCookie(goodBakedCookie)
	DefaultHTTPPasswdChangeHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 400 {
		t.Errorf("passwd change handler responded with non-400 response for empty passwords in request")
	}

	incorrectCurrentPasswdChangeInput := `{
    "currentPassword":"$1*",
    "newPassword":"$2"
  }`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/swoossh/changePasswd", strings.NewReader(incorrectCurrentPasswdChangeInput))
	r.AddCookie(goodBakedCookie)
	DefaultHTTPPasswdChangeHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 400 {
		t.Errorf("passwd change handler responded with non-400 response for mismatched current password in request")
	}
}
