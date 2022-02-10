package httpserver

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ChandraNarreddy/siv"
	"github.com/ChandraNarreddy/swoossh/ca"
	"golang.org/x/crypto/ssh"
)

type mockCA struct{}

func (c *mockCA) SignCert(csr ca.CSR) (*ssh.Certificate, error) {
	keyPEM := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS1CjjPe6sc0375DuAKpU84yhFX4qWM
rvfr3fuhg4yoTsK7G8tc5ryO7I/azKBuo5ICThSqQkbnPqzp9ojclsP5AAAAwEzr071M69
O9AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO
4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/
kAAAAgXT6Abfcw/mi4sNJPudZzHnHZyCvvrGFkeTnSK9F9ZkMAAAAjY2hhbmRyYWthbnRo
cmVkZHlATWFjQm9vay1Qcm8ubG9jYWwBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	signer, _ := ssh.ParsePrivateKey([]byte(keyPEM))
	cert := &ssh.Certificate{
		Key:          pub,
		SignatureKey: pub,
		ValidBefore:  uint64(time.Now().Add(10 * time.Minute).Unix()),
	}
	cert.SignCert(rand.Reader, signer)
	return cert, nil
}
func (c *mockCA) RandomProvider() (io.Reader, error)               { return nil, nil }
func (c *mockCA) RefreshKeys() error                               { return nil }
func (c *mockCA) GetHostCertSigner(csr ca.CSR) (ssh.Signer, error) { return nil, nil }
func (c *mockCA) GetUserCertSigner(csr ca.CSR) (ssh.Signer, error) { return nil, nil }
func (c *mockCA) CertSerialGenerator() func(csr ca.CSR) (uint64, error) {
	return func(ca.CSR) (uint64, error) { return uint64(0), nil }
}

func TestDefaultHTTPServerCreateSSHUserCertHandler(t *testing.T) {
	testCreateTestUser(t)
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
		AdminUserClaimsMatches:        []string{"admin"},
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
	validAuthenticatedReq := httptest.NewRequest(http.MethodGet, "/swoossh/myNewCert", nil)
	validAuthenticatedReq.AddCookie(goodBakedCookie)

	goodAdminCookie := &cookie{
		Principal: "email@email.com",
		Expiry:    time.Now().Add(10 * time.Minute).Unix(),
		IsAdmin:   true,
	}
	goodAdminBakedCookie, _ := bakeCookie(goodAdminCookie, siv, "test_cookie", "https")
	validAdminAuthenticatedReq := httptest.NewRequest(http.MethodGet, "/swoossh/admin/Cert/User/Name/smith/NewCert", nil)
	validAdminAuthenticatedReq.AddCookie(goodAdminBakedCookie)
	testCases := []struct {
		testcase string
		r        *http.Request
		w        *httptest.ResponseRecorder
	}{
		{
			testcase: "valid-user",
			r:        validAuthenticatedReq,
			w:        httptest.NewRecorder(),
		},
		{
			testcase: "valid-admin_user",
			r:        validAdminAuthenticatedReq,
			w:        httptest.NewRecorder(),
		},
	}
	for _, each := range testCases {
		switch each.testcase {
		case "valid-user":
			DefaultHTTPServerCreateSSHUserCertHandler(each.w, each.r, genericDefaultHTTPServer)
			if each.w.Result().StatusCode != 200 {
				t.Errorf("create ssh cert handler responded with non-200 response for valid request")
			}
		case "valid-admin_user":
			DefaultHTTPServerCreateSSHUserCertHandler(each.w, each.r, genericDefaultHTTPServer)
			if each.w.Result().StatusCode != 200 {
				t.Errorf("create ssh cert handler responded with non-200 response for valid admin request")
			}
		}
	}
}

func TestDefaultHTTPServerGetCertsForUserHandler(t *testing.T) {
	testCreateTestUser(t)
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
		AdminUserClaimsMatches:        []string{"admin"},
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
	validAuthenticatedCreateReq := httptest.NewRequest(http.MethodGet, "/swoossh/myNewCert", nil)
	validAuthenticatedCreateReq.AddCookie(goodBakedCookie)

	goodAdminCookie := &cookie{
		Principal: "email@email.com",
		Expiry:    time.Now().Add(10 * time.Minute).Unix(),
		IsAdmin:   true,
	}
	goodAdminBakedCookie, _ := bakeCookie(goodAdminCookie, siv, "test_cookie", "https")
	validAdminAuthenticatedCreateReq := httptest.NewRequest(http.MethodGet, "/swoossh/admin/Cert/User/Name/smith/NewCert", nil)
	validAdminAuthenticatedCreateReq.AddCookie(goodAdminBakedCookie)

	for i := 0; i < 10; i++ {
		r := validAuthenticatedCreateReq
		w := httptest.NewRecorder()
		DefaultHTTPServerCreateSSHUserCertHandler(w, r, genericDefaultHTTPServer)
		time.Sleep(time.Second)
		ar := validAdminAuthenticatedCreateReq
		aw := httptest.NewRecorder()
		DefaultHTTPServerCreateSSHUserCertHandler(aw, ar, genericDefaultHTTPServer)
	}

	validAuthenticatedGetReq := httptest.NewRequest(http.MethodGet, "/swoossh/myCerts?size=5&token=&order=forw", nil)
	validAuthenticatedGetReq.AddCookie(goodBakedCookie)

	validAdminAuthenticatedGetReq := httptest.NewRequest(http.MethodGet, "/swoossh/admin/Cert/User/Name/smith/list?size=10&token=&order=forw", nil)
	validAdminAuthenticatedGetReq.AddCookie(goodAdminBakedCookie)

	testCases := []struct {
		testcase string
		r        *http.Request
		w        *httptest.ResponseRecorder
	}{
		{
			testcase: "valid-user",
			r:        validAuthenticatedGetReq,
			w:        httptest.NewRecorder(),
		},
		{
			testcase: "valid-admin_user",
			r:        validAdminAuthenticatedGetReq,
			w:        httptest.NewRecorder(),
		},
	}
	for _, each := range testCases {
		switch each.testcase {
		case "valid-user":
			DefaultHTTPServerGetCertsForUserHandler(each.w, each.r, genericDefaultHTTPServer)
			if each.w.Result().StatusCode != 200 {
				t.Errorf("get ssh cert handler responded with non-20 response for valid request")
			}
			bodyBytes, _ := io.ReadAll(each.w.Result().Body)
			var bodyJSON map[string]map[string]interface{}
			json.Unmarshal(bodyBytes, &bodyJSON)
			certs, _ := bodyJSON["data"]["certs"].([]interface{})
			if len(certs) != 5 {
				t.Errorf("get ssh cert handler did not return the number of certs asked for valid request")
			}
		case "valid-admin_user":
			DefaultHTTPServerGetCertsForUserHandler(each.w, each.r, genericDefaultHTTPServer)
			if each.w.Result().StatusCode != 200 {
				t.Errorf("get ssh cert handler responded with non-200 response for valid admin request")
			}
			bodyBytes, _ := io.ReadAll(each.w.Result().Body)
			var bodyJSON map[string]map[string]interface{}
			json.Unmarshal(bodyBytes, &bodyJSON)
			certs, _ := bodyJSON["data"]["certs"].([]interface{})
			if len(certs) != 10 {
				t.Errorf("get ssh cert handler did not return the number of certs asked for valid admin request")
			}
		}
	}
}
