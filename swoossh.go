package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ChandraNarreddy/siv"
	"github.com/ChandraNarreddy/swoossh/ca"
	"github.com/ChandraNarreddy/swoossh/httpserver"
	"github.com/ChandraNarreddy/swoossh/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	oidc "github.com/coreos/go-oidc"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
)

//go:embed static
var content embed.FS

//go:embed templates
var templates embed.FS

func main() {
	//parse flags
	var stagevar string
	flag.StringVar(&stagevar, "stage", "dev", "Specify the stage for this deployment - prod or dev. Defaults to dev")
	flag.Parse()

	//figure out the stage
	stage, err := StageOut(strings.ToLower(stagevar))
	if err != nil {
		log.Fatalf("Incorrect stage value passed = %v", stagevar)
	}
	config, err := configParser(stage)
	if err != nil {
		log.Fatalf("Failed to parse config %+v", err)
	}
	//create a log file for this service
	now := time.Now()
	logFile := fmt.Sprintf(config.LogFilePrefix+"-%d-%d-%d-%d:%d:%d.log", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())

	//create logger here
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening logging file: %v", err)
	}
	defer f.Close()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix(config.LogPrefix + " ")
	log.SetOutput(f)

	//creating an aws session here for dynamodb storage
	sess := session.Must(session.NewSession())
	ddbClient := dynamodb.New(sess, aws.NewConfig().WithRegion(config.Storage.DDBAWSRegion))
	//creating store here
	ddbStore := &storage.DefaultDynamoDBStore{
		DDBClient:                  ddbClient,
		TableName:                  &config.Storage.DDBTableName,
		GSIPosixIDIndexName:        &config.Storage.GSIPosixIDIndexName,
		GSIUUIDIndexName:           &config.Storage.GSIUUIDIndexName,
		GSISecondaryGroupIndexName: &config.Storage.GSISecondaryGroupsIndexName,
		GSINameIndexName:           &config.Storage.GSINameIndexName,
		GSIEmailIndexName:          &config.Storage.GSIEmailIndexName,
		GSITypeIndexName:           &config.Storage.GsiTypeIndexName,
	}

	//creating CA here
	hostSecretSvc := secretsmanager.New(sess, aws.NewConfig().WithRegion(config.CAServer.HostCertSignerKey.SecretRegion))
	userSecretSvc := secretsmanager.New(sess, aws.NewConfig().WithRegion(config.CAServer.UserCertSignerKey.SecretRegion))
	awsCA, caErr := ca.NewAWSDefaultCA(config.CAServer.HostCertSignerKey.SecretEntry,
		hostSecretSvc,
		config.CAServer.UserCertSignerKey.SecretEntry,
		userSecretSvc,
		30, 5)
	if caErr != nil {
		log.Fatalf("Failed to create AWS Default CA - %+v", caErr)
	}

	//creating oAuth Client here
	oAuthClientSecret, fetchErr := fetchAWSSecret(sess,
		config.HttpServer.OauthConfig.ClientSecret.SecretRegion,
		config.HttpServer.OauthConfig.ClientSecret.SecretEntry)
	if fetchErr != nil {
		log.Fatalf("Could not fetch oauth client secret - %+v", fetchErr)
	}

	oauthEndpoint := oauth2.Endpoint{
		AuthURL:  config.HttpServer.OauthConfig.OauthEndPointAuthURL,
		TokenURL: config.HttpServer.OauthConfig.OauthEndPointTokenURL,
	}
	clientCfg := &oauth2.Config{
		ClientID:     config.HttpServer.OauthConfig.ClientID,
		ClientSecret: string(oAuthClientSecret),
		Endpoint:     oauthEndpoint,
		Scopes:       config.HttpServer.OauthConfig.Scopes,
	}

	oidcProvider, oidcProviderErr := oidc.NewProvider(context.Background(),
		config.HttpServer.OauthConfig.OIDCIssuerURL)
	if oidcProviderErr != nil {
		log.Fatalf("Failed to obtain oidc provider details - %+v", oidcProviderErr)
	}

	oAuthClient := &httpserver.OauthClient{
		OauthConfig:                httpserver.OauthConfig{Config: clientCfg},
		OpenIDCProvider:            httpserver.OIDCProvider{Provider: oidcProvider},
		OauthCallBackHandlerPath:   &config.HttpServer.OauthConfig.OauthCallBackHandlerPath,
		OauthStateParamName:        &config.HttpServer.OauthConfig.OauthStateParamName,
		EntitlementsFieldForClaims: &config.HttpServer.OauthConfig.OauthClaimsEntitlementsField,
	}

	//creating AuthHandler here
	apiCreds := make([]*httpserver.ApiKeyCreds, 0)
	for _, cred := range config.HttpServer.APIKeyCreds {
		key, fetchKeyErr := fetchAWSSecret(sess, cred.ApiKeySecret.SecretRegion, cred.ApiKeySecret.SecretEntry)
		if fetchKeyErr != nil {
			log.Fatalf("Could not fetch the API Secret for Key ID %s - %+v", cred.ApiKeyID, fetchKeyErr)
		}
		apiCred := &httpserver.ApiKeyCreds{
			ApiKeyID: cred.ApiKeyID,
			ApiKey:   key,
		}
		apiCreds = append(apiCreds, apiCred)
	}
	if len(apiCreds) == 0 {
		log.Printf("HTTP Server is starting up without any admin API Key defined!!!")
	}

	cookieSecret, fetchErr := fetchAWSSecret(sess,
		config.HttpServer.CookieSecret.SecretRegion,
		config.HttpServer.CookieSecret.SecretEntry)

	if fetchErr != nil {
		log.Fatalf("Could not fetch the cookie secret - %+v", fetchErr)
	}

	keypair, aesSIVErr := siv.NewAesSIVBlockPair(cookieSecret)
	if aesSIVErr != nil {
		log.Fatalf("Could not initialize SIV block pair using cookie secret - %+v", aesSIVErr)
	}
	siv, sivErr := siv.NewSIV(keypair)
	if sivErr != nil {
		log.Fatalf("Could not initialize SIV for cookie encryption - %+v", sivErr)
	}
	validity := int64(config.HttpServer.ApiKeySignatureValiditySecs)
	authHandler := &httpserver.DefaultHTTPServerAuthHandler{
		AuthzCreds:                    apiCreds,
		ApiKeySignatureValidityInSecs: &validity,
		ApiKeyAuthzReqHeader:          &config.HttpServer.ApiKeyAuthzReqHeader,
		OAuthClient:                   oAuthClient,
		CookieKey:                     &config.HttpServer.CookieKey,
		Siv:                           siv,
		AdminUserClaimsMatches:        config.HttpServer.AdminUserClaimsMatches,
	}

	srv := &httpserver.DefaultHTTPServer{
		Store:             ddbStore,
		CA:                awsCA,
		AuthHandler:       authHandler,
		TemplateFS:        templates,
		AdminHomeTmplName: &config.HttpServer.AdminHomeTmplName,
		HomeTmplName:      &config.HttpServer.HomeTmplName,
	}

	//Now creating a webserver and registering handlers
	router := httprouter.New()
	router.HandlerFunc("GET", "/swoossh/home", srv.HomeHandler)
	router.HandlerFunc("GET", "/swoossh/", srv.HomeHandler)
	router.HandlerFunc("GET", config.HttpServer.OauthConfig.OauthCallBackHandlerPath, srv.HomeHandler)
	router.HandlerFunc("POST", "/swoossh/changePasswd", srv.PasswdChangeHandler)
	router.HandlerFunc("GET", "/swoossh/myNewCert", srv.CreateSSHUserCertHandler)
	router.HandlerFunc("GET", "/swoossh/admin/Cert/User/Name/:principalName/NewCert", srv.CreateSSHUserCertHandler)
	router.HandlerFunc("GET", "/swoossh/admin/Cert/User/Name/:principalName/list", srv.GetCertsForUserHandler)
	router.HandlerFunc("GET", "/swoossh/myCerts", srv.GetCertsForUserHandler)
	router.HandlerFunc("GET", "/swoossh/admin/Group/ID/:uuid", srv.GetGroupHandler)
	router.HandlerFunc("GET", "/swoossh/admin/Group/Name/:groupname", srv.GetGroupHandler)
	//router.HandlerFunc("PUT", "/swoossh/admin/Group/ID/:uuid", srv.PutGroupHandler)
	router.HandlerFunc("PUT", "/swoossh/admin/Group/Name/:groupName", srv.PutGroupHandler)
	router.HandlerFunc("POST", "/swoossh/admin/Group", srv.PostGroupHandler)
	router.HandlerFunc("DELETE", "/swoossh/admin/Group/Name/:groupName", srv.DeleteGroupHandler)
	router.HandlerFunc("GET", "/swoossh/admin/Groups", srv.SearchGroupsHandler)
	router.HandlerFunc("GET", "/swoossh/admin/User/ID/:uuid", srv.GetUserHandler)
	router.HandlerFunc("GET", "/swoossh/admin/User/Name/:principalName", srv.GetUserHandler)
	router.HandlerFunc("PUT", "/swoossh/admin/User/Name/:principalName", srv.PutUserHandler)
	router.HandlerFunc("PUT", "/swoossh/admin/User/ID/:uuid", srv.PutUserHandler)
	router.HandlerFunc("PUT", "/swoossh/User/ID/:uuid", srv.PutUserHandlerNonAdmin)
	router.HandlerFunc("POST", "/swoossh/admin/User", srv.PostUserHandler)
	router.HandlerFunc("DELETE", "/swoossh/admin/User/Name/:principalName", srv.DeleteUserHandler)
	router.HandlerFunc("GET", "/swoossh/admin/Users", srv.SearchUsersHandler)
	router.ServeFiles("/swoossh/pub/*filepath", http.FS(content))

	server := &http.Server{
		ReadTimeout:  50 * time.Second,
		WriteTimeout: 600 * time.Second,
		IdleTimeout:  60 * time.Second,
		Addr:         config.HttpServer.Addr,
		Handler:      router,
	}
	log.Fatalf("Swoossh http server died - %+v", server.ListenAndServe())
}
