package httpserver

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ChandraNarreddy/siv"
	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/storage"
	"github.com/ChandraNarreddy/swoossh/user"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/coreos/go-oidc"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

var localDDBEndpoint = "http://localhost:8000"
var tableName = "CAStore"
var ddbStore = &storage.DefaultDynamoDBStore{
	TableName:                  strPtr("CAStore"),
	GSIPosixIDIndexName:        strPtr("gsi_posix_id"),
	GSIUUIDIndexName:           strPtr("gsi_uuid"),
	GSISecondaryGroupIndexName: strPtr("gsi_secondary_group"),
	GSINameIndexName:           strPtr("gsi_name"),
	GSIEmailIndexName:          strPtr("gsi_email"),
	GSITypeIndexName:           strPtr("gsi_type"),
}
var forw = storage.DDBQueryOrder(1)
var rev = storage.DDBQueryOrder(2)

func localDDBClient() *dynamodb.DynamoDB {
	cfg := aws.Config{
		Endpoint:    aws.String(localDDBEndpoint),
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials("dummy", "dummy", ""),
	}
	sess := session.Must(session.NewSession(&cfg))
	return dynamodb.New(sess)
}

func cleanUpDB() error {
	client := localDDBClient()
	tableDeleteInput := &dynamodb.DeleteTableInput{
		TableName: aws.String(tableName),
	}
	log.Printf("Cleaning up the DB.")
	if _, err := client.DeleteTable(tableDeleteInput); err != nil {
		log.Printf("Got error calling delete table: %s", err)
		return err
	}
	tableCreateInput := &dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("pk"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("sk"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("name"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("uuid"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("type"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("posix_id"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("secondary_group"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("email"),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("pk"),
				KeyType:       aws.String("HASH"),
			},
			{
				AttributeName: aws.String("sk"),
				KeyType:       aws.String("RANGE"),
			},
		},
		GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
			{
				IndexName: aws.String("gsi_posix_id"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("posix_id"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("type"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_uuid"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("uuid"),
						KeyType:       aws.String("HASH"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_secondary_group"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("secondary_group"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("pk"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_name"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("name"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("type"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_email"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("email"),
						KeyType:       aws.String("HASH"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_type"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("type"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("pk"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
		},
		BillingMode: aws.String("PROVISIONED"),
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
		TableName: aws.String(tableName),
	}
	log.Printf("Adding table to the DB.")
	if _, err := client.CreateTable(tableCreateInput); err != nil {
		log.Printf("Got error calling create table: %s", err)
		return err
	}
	return nil
}

func strPtr(i string) *string {
	return &i
}
func intPtr(i int) *int {
	return &i
}
func int64Ptr(i int64) *int64 {
	return &i
}
func uint16Ptr(i int) *uint16 {
	k := uint16(i)
	return &k
}
func uint32Ptr(i int) *uint32 {
	k := uint32(i)
	return &k
}

type mockOIDCProvider struct {
	verifier *mockOIDCVerifier
}

func (c *mockOIDCProvider) Verifier(config *oidc.Config) IDTokenVerifierInterface {
	return c.verifier
}

type mockOIDCVerifier struct {
	token *mockOIDCToken
}

func (c *mockOIDCVerifier) Verify(ctx context.Context, rawIDToken string) (IDTokenInterface, error) {
	return c.token, nil
}

type mockOIDCToken struct {
	email         string
	emailVerified bool
	expiry        float64
	entitlements  []string
}

func (c *mockOIDCToken) Claims(v interface{}) error {
	claims := v.(*oAuthClaims)
	claims.Email = c.email //"email@email.com"
	claims.EmailVerified = c.emailVerified
	claims.Expiry = c.expiry             //float64(time.Now().Add(time.Minute * 10).Unix())
	claims.Entitlements = c.entitlements //[]string{"admin"}
	claims.EntitlementsField = ""
	return nil
}

type mockOauth2Token struct{}

func (c *mockOauth2Token) Extra(key string) interface{} {
	return ""
}

type mockOauthConfig struct {
	clientID string
}

func (c *mockOauthConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (OauthTokenInterface, error) {
	return &mockOauth2Token{}, nil
}
func (c *mockOauthConfig) ClientID() string {
	return c.clientID
}

type mockOauthClient struct {
	oidcProvider *mockOIDCProvider
}

func (c *mockOauthClient) SetOauthRedirectURL(baseHost string, scheme string) {}
func (c *mockOauthClient) GetOauthRedirectPath() string {
	return "/oauth2/redirect"
}
func (c *mockOauthClient) GetAuthCodeURL(state string) string {
	u := url.URL{
		Scheme: "http",
		Host:   "localhost",
		Path:   "login/oauth/authorize",
	}
	v := url.Values{}
	v.Set("state", state)
	u.RawQuery = v.Encode()
	return u.String()
}
func (c *mockOauthClient) OAuthStateParamName() string {
	return "state"
}
func (c *mockOauthClient) OAuthConfig() OauthConfigInterface {
	return &mockOauthConfig{
		clientID: "test",
	}
}
func (c *mockOauthClient) GetOpenIDCProvider() OIDCProviderInterface {
	return c.oidcProvider
}
func (c *mockOauthClient) GetEntitlementsFieldForClaims() string {
	return ""
}

func TestAuthorizationHandler(t *testing.T) {
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
	}
	authHandlers := []DefaultHTTPServerAuthHandler{
		genericAuthHandler,
		genericAuthHandler,
		genericAuthHandler,
		genericAuthHandler,
	}
	authHandlers[0].OAuthClient = &mockOauthClient{
		oidcProvider: &mockOIDCProvider{
			verifier: &mockOIDCVerifier{
				token: &mockOIDCToken{
					email:         "email@email.com",
					emailVerified: true,
					expiry:        float64(time.Now().Add(time.Minute * 10).Unix()),
					entitlements:  []string{"admin"},
				},
			},
		},
	}
	authHandlers[1].OAuthClient = &mockOauthClient{
		oidcProvider: &mockOIDCProvider{
			verifier: &mockOIDCVerifier{
				token: &mockOIDCToken{
					email:         "email@email.com",
					emailVerified: true,
					expiry:        float64(time.Now().Add(time.Minute * 10).Unix()),
					entitlements:  []string{"not-admin"},
				},
			},
		},
	}
	authHandlers[2].OAuthClient = &mockOauthClient{
		oidcProvider: &mockOIDCProvider{
			verifier: &mockOIDCVerifier{
				token: &mockOIDCToken{},
			},
		},
	}
	authHandlers[3].OAuthClient = &mockOauthClient{
		oidcProvider: &mockOIDCProvider{
			verifier: &mockOIDCVerifier{
				token: &mockOIDCToken{},
			},
		},
	}
	validOAuthState, _ := generateOauthState("/authorized_endpoint", siv)
	validOauthRedirectPath := fmt.Sprintf("/oauth2/redirect?code=somecode&state=%s", validOAuthState)
	incorrectStateOauthRedirectPath := fmt.Sprintf("/oauth2/redirect?code=somecode&state=%s", "invalid")
	nilStateOauthRedirectPath := fmt.Sprint("/oauth2/redirect?code=somecode&state=")
	goodAdminCookie := &cookie{
		Principal: "email@email.com",
		Expiry:    time.Now().Add(10 * time.Minute).Unix(),
		IsAdmin:   true,
	}
	goodAdminBakedCookie, _ := bakeCookie(goodAdminCookie, siv, "test_cookie", "https")
	validAdminAuthenticatedReq := httptest.NewRequest(http.MethodGet, "/authenticated", nil)
	validAdminAuthenticatedReq.AddCookie(goodAdminBakedCookie)
	goodCookie := &cookie{
		Principal: "email@email.com",
		Expiry:    time.Now().Add(10 * time.Minute).Unix(),
		IsAdmin:   false,
	}
	goodBakedCookie, _ := bakeCookie(goodCookie, siv, "test_cookie", "https")
	validAuthenticatedReq := httptest.NewRequest(http.MethodGet, "/authenticated", nil)
	validAuthenticatedReq.AddCookie(goodBakedCookie)
	expiredCookie := &cookie{
		Principal: "email@email.com",
		Expiry:    time.Now().Add(-10 * time.Minute).Unix(),
		IsAdmin:   false,
	}
	expiredBakedCookie, _ := bakeCookie(expiredCookie, siv, "test_cookie", "https")
	expiredAuthenticatedReq := httptest.NewRequest(http.MethodGet, "/authenticated", nil)
	expiredAuthenticatedReq.AddCookie(expiredBakedCookie)
	invaldUserCookie := &cookie{
		Principal: "mask@email.com",
		Expiry:    time.Now().Add(10 * time.Minute).Unix(),
		IsAdmin:   false,
	}
	invaldUserBakedCookie, _ := bakeCookie(invaldUserCookie, siv, "test_cookie", "https")
	invaldUserAuthenticatedReq := httptest.NewRequest(http.MethodGet, "/authenticated", nil)
	invaldUserAuthenticatedReq.AddCookie(invaldUserBakedCookie)

	validSigReq := httptest.NewRequest(http.MethodPost, "/usersearch?filter=[org1,org2,org3]&area={122,399}&perms=open", strings.NewReader(`{"test_acc": "12124", "valid_user": false, "name": "creation"}`))
	validSigReq.Header.Add("cookie", "test-cookie=vkdfldvkdfvdl;someothercookie=cdkscnvcsdn")
	validSigReq.Header.Add("referer", "https://www.swoossh.com/")
	validSig, _ := GenerateSignatureHeader_v1(validSigReq, *genericAuthHandler.AuthzCreds[0], []string{"cookie", "referer"})
	validSigReq.Header.Add("Authorization", *validSig)

	inValidSigReq := httptest.NewRequest(http.MethodPost, "/usersearch?filter=[org1,org2,org3]&area={122,399}&perms=open", strings.NewReader(`{"test_acc": "12124", "valid_user": false, "name": "creation"}`))
	inValidSigReq.Header.Add("cookie", "test-cookie=vkdfldvkdfvdl;someothercookie=cdkscnvcsdn")
	inValidSigReq.Header.Add("referer", "https://www.swoossh.com/")
	inValidSig, _ := GenerateSignatureHeader_v1(inValidSigReq, *genericAuthHandler.AuthzCreds[0], []string{"cookie", "referer"})
	inValidSigReq.Header.Set("cookie", "test-cookie=vkdfldvkdfvdl;")
	inValidSigReq.Header.Add("Authorization", *inValidSig)

	testCases := []struct {
		testcase          string
		authHandler       *DefaultHTTPServerAuthHandler
		oAuthState        string
		oauthRedirectPath string
		r                 *http.Request
		w                 *httptest.ResponseRecorder
	}{
		{
			testcase:    "valid-admin",
			authHandler: &authHandlers[0],
			r:           httptest.NewRequest(http.MethodGet, validOauthRedirectPath, nil),
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "non-admin",
			authHandler: &authHandlers[1],
			r:           httptest.NewRequest(http.MethodGet, validOauthRedirectPath, nil),
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "incorrect-claims",
			authHandler: &authHandlers[2],
			r:           httptest.NewRequest(http.MethodGet, validOauthRedirectPath, nil),
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "nil-state",
			authHandler: &authHandlers[1],
			r:           httptest.NewRequest(http.MethodGet, nilStateOauthRedirectPath, nil),
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "incorrect-state",
			authHandler: &authHandlers[1],
			r:           httptest.NewRequest(http.MethodGet, incorrectStateOauthRedirectPath, nil),
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "valid_auth_admin_request",
			authHandler: &authHandlers[0],
			r:           validAdminAuthenticatedReq,
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "valid_auth_normal_request",
			authHandler: &authHandlers[1],
			r:           validAuthenticatedReq,
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "expiredAuthenticatedReq",
			authHandler: &authHandlers[1],
			r:           expiredAuthenticatedReq,
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "invaldUserAuthenticatedReq",
			authHandler: &authHandlers[1],
			r:           invaldUserAuthenticatedReq,
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "valdSigntureRequest",
			authHandler: &authHandlers[3],
			r:           validSigReq,
			w:           httptest.NewRecorder(),
		},
		{
			testcase:    "inValdSigntureRequest",
			authHandler: &authHandlers[3],
			r:           inValidSigReq,
			w:           httptest.NewRecorder(),
		},
	}

	testCreateTestUser(t)
	for _, each := range testCases {
		switch each.testcase {
		case "valid-admin":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr != nil {
				t.Errorf("authorization handler threw error - %+v", authErr)
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request to oAuth redirection path")
			}
			if ok := result.IsAdmin(); ok == nil || !*ok {
				t.Errorf("authorization handler could not identify the caller as admin")
			}
			cookieVal := each.w.Result().Cookies()[0].Value
			var k cookie
			cookieExpired, cookieErr := indulgeCookie(&k, cookieVal, each.authHandler.Siv)
			if cookieErr != nil {
				t.Errorf("Cookie reading error")
			}
			if *cookieExpired {
				t.Errorf("Cookie has already expired")
			}
			if !k.IsAdmin {
				t.Errorf("Cookie's IsAdmin flag is not set")
			}
		case "non-admin":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr != nil {
				t.Errorf("authorization handler threw error - %+v", authErr)
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request to oAuth redirection path")
			}
			if ok := result.IsAdmin(); ok != nil {
				t.Errorf("authorization handler identified caller as admin")
			}
			cookieVal := each.w.Result().Cookies()[0].Value
			var k cookie
			cookieExpired, cookieErr := indulgeCookie(&k, cookieVal, each.authHandler.Siv)
			if cookieErr != nil {
				t.Errorf("Cookie reading error")
			}
			if *cookieExpired {
				t.Errorf("Cookie has already expired")
			}
			if k.IsAdmin {
				t.Errorf("Cookie's IsAdmin flag is set")
			}
			location, locationErr := each.w.Result().Location()
			if locationErr != nil {
				t.Errorf("Error occurred while extracting location header from successful oauth response")
			}
			if location.EscapedPath() != "/authorized_endpoint" {
				t.Errorf("Location header in successful oauth response does not match with expectation")
			}
		case "incorrect-claims":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr == nil {
				t.Errorf("authorization handler did not throw error")
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request")
			}
			if usr, err := result.AuthenticatedPrincipal(); usr != nil || err == nil {
				t.Errorf("authorization handler result's principal is not null for incorrect claims")
			}
		case "nil-state":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr == nil {
				t.Errorf("authorization handler did not throw error")
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request")
			}
			if usr, err := result.AuthenticatedPrincipal(); usr != nil || err == nil {
				t.Errorf("authorization handler result's principal is not null for incorrect claims")
			}
		case "incorrect-state":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr == nil {
				t.Errorf("authorization handler did not throw error")
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request")
			}
			if usr, err := result.AuthenticatedPrincipal(); usr != nil || err == nil {
				t.Errorf("authorization handler result's principal is not null for incorrect claims")
			}
		case "valid_auth_admin_request":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr != nil {
				t.Errorf("authorization handler has thrown error for valid authenticated request")
			}
			if fulfilled {
				t.Errorf("authorization handler has fulfilled request for valid authenticated request")
			}
			if usr, err := result.AuthenticatedPrincipal(); err != nil || usr == nil {
				t.Errorf("authenticated principal is nil for valid authenticated request")
			}
			if result.IsAdmin() == nil || !*result.IsAdmin() {
				t.Errorf("authenticated principal is nil or not admin for valid authenticated request")
			}
		case "valid_auth_normal_request":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr != nil {
				t.Errorf("authorization handler has thrown error for valid authenticated request")
			}
			if fulfilled {
				t.Errorf("authorization handler has fulfilled request for valid authenticated request")
			}
			if usr, err := result.AuthenticatedPrincipal(); err != nil || usr == nil {
				t.Errorf("authenticated principal is nil for valid authenticated request")
			}
			if result.IsAdmin() == nil || *result.IsAdmin() {
				t.Errorf("authenticated principal is nil or admin for valid authenticated request")
			}
		case "expiredAuthenticatedReq":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr == nil {
				t.Errorf("authorization handler has not thrown error for expired authenticated request")
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request for expired authenticated request")
			}
			if result, err := result.AuthorizationResult(); result != nil || err == nil {
				t.Errorf("authorization handler has not returned nil auth result for expired authenticated request")
			}
			if each.w.Result().Cookies()[0].Value != "" && each.w.Result().Cookies()[0].MaxAge != -1 {
				t.Errorf("authorization handler has not returned delete cookie in response to expired authenticated request")
			}
		case "invaldUserAuthenticatedReq":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr == nil {
				t.Errorf("authorization handler has not thrown error for invalid user authenticated request")
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request for invalid user authenticated request")
			}
			if res, err := result.AuthorizationResult(); res == nil || *res || err != nil {
				t.Errorf("authorization handler has not returned nil auth result for invalid user authenticated request")
			}
		case "valdSigntureRequest":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr != nil {
				t.Errorf("authorization handler has thrown error for valid signature request")
			}
			if fulfilled {
				t.Errorf("authorization handler has fulfilled request for valid signature request")
			}
			if res, err := result.AuthorizationResult(); err != nil || res == nil || !*res {
				t.Errorf("authenticated principal is nil for valid signature request")
			}
			if result.IsAdmin() == nil || !*result.IsAdmin() {
				t.Errorf("authenticated principal is nil or admin for valid signature request")
			}
		case "inValdSigntureRequest":
			result, fulfilled, authErr := each.authHandler.AuthorizationHandler(each.w, each.r, ddbStore)
			if authErr == nil {
				t.Errorf("authorization handler has not thrown error for invalid signature request")
			}
			if !fulfilled {
				t.Errorf("authorization handler has not fulfilled request for invalid signature request")
			}
			if res, err := result.AuthorizationResult(); res == nil || *res || err != nil {
				t.Errorf("authorization handler has not returned nil auth result for invalid user authenticated request")
			}
		}
	}
}

func TestCheckCallerExists(t *testing.T) {

}

func TestValidateSignature(t *testing.T) {

}

func testCreateTestUser(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	grp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(345),
		Name: strPtr("secGrp1"),
	}
	secGrps := []group.PosixGroup{
		grp,
	}
	usr := storage.DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("smith"),
			UID:              uint32Ptr(123),
			PublicKey:        pub,
			PrimaryGroup:     primGrp,
			SecondaryGroups:  secGrps,
			LatestPasswdHash: strPtr("$1"),
			SudoClaims: []string{
				"smith locahost = /var/www/apache",
				"smith	locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	ddbSecGrp := storage.DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("gpr"),
		DefaultPosixGroup:     grp,
	}
	if e := storage.DefaultDynamoDBStoreCreateGroup(ddbSecGrp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	if e := storage.DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}
}
