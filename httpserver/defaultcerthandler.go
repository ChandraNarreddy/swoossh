package httpserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ChandraNarreddy/swoossh/ca"
	"github.com/ChandraNarreddy/swoossh/sshcert"
	"github.com/ChandraNarreddy/swoossh/storage"
	"github.com/ChandraNarreddy/swoossh/user"
	"golang.org/x/crypto/ssh"
)

var (
	GetCertsForUserByPrimaryNameAdminPrefixPath = "/swoossh/admin/Cert/User/Name/"
	GetCertsForUserByPrimaryNameAdminSuffixPath = "/list"

	CreateCertForUserAdminPrefixPath = "/swoossh/admin/Cert/User/Name/"
	CreateCertForUserAdminSuffixPath = "/NewCert"

	GetCertsSizeQueryParamName  = "size"
	GetCertsTokenQueryParamName = "token"
	GetCertsOrderQueryParamName = "order"

	MAXCERTPAYLOADBODYSIZE         = 1048576
	GetCertsDefaultResultSize      = 20
	GetCertsOrderValueEnumForward  = "forw"
	GetCertsOrderValueEnumPrevious = "prev"
)

//for requests GET /swoossh/myNewCert
//for requests GET /swoossh/admin/Cert/User/Name/:xxx/NewCert creates and returns a new certificate
func DefaultHTTPServerCreateSSHUserCertHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {
	store := srv.Store
	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-25-10")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-25-11")
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to create SSH cert for this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-25-12")
		return
	}

	sshPutter, ok := store.(storage.PutSSHCert)
	if !ok {
		log.Print("Store does not implement PutSSHCert interface, cannot fulfill request")
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-25-13")
		return
	}

	var usr user.User

	var adminRequest bool
	//if call was to Admin API -
	if val := strings.TrimPrefix(r.URL.Path, CreateCertForUserAdminPrefixPath); val != r.URL.Path {
		if name := strings.TrimSuffix(val, CreateCertForUserAdminSuffixPath); name != val {
			if !*authnzResult.IsAdmin() {
				log.Print("Caller is not admin")
				writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-25-14")
				return
			}
			principalName := &name
			if principalName == nil {
				log.Print("principalName not found in request")
				writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-25-15")
				return
			}
			userFilter := &storage.DefaultStoreUserFilter{
				PricipalNameProjection: principalName,
			}
			var getUserErr error
			usr, getUserErr = store.GetUser(userFilter)
			if getUserErr != nil {
				log.Printf("Error while retrieving user with filter %+v - %+v", userFilter, getUserErr)
				writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-25-16")
				return
			}
			if usr == nil {
				log.Printf("No user found for the filter %+v", userFilter)
				writeError(w, http.StatusNotFound, "User Not Found", "Err-25-17")
				return
			}
		} else {
			writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-25-18")
			return
		}
		adminRequest = true
	} else { //Non-admin API routes

		var authenticationErr error
		usr, authenticationErr = authnzResult.AuthenticatedPrincipal()
		if authenticationErr != nil {
			log.Printf("Failed to ID the user, quitting.")
			writeError(w, http.StatusUnauthorized, "Unknown user", "Err-25-29")
			return
		}
	}

	validatingPosixCert := &sshcert.DefaultCertPosixAccount{
		Cert:                &ssh.Certificate{},
		UIDKey:              sshcert.DefaultUserCertExtUIDKey,
		PrimaryGroupKey:     sshcert.DefaultUserCertExtPrimaryGroupKey,
		SecondaryGroupsKey:  sshcert.DefaultUserCertExtSecondaryGroupsKey,
		SudoClaimsKey:       sshcert.DefaultUserCertExtSudoClaimsKey,
		LatestPasswdHashKey: sshcert.DefaultUserCertExtLatestPasswdHashKey,
	}

	usrPubKey := usr.GetPublicKey()
	if usrPubKey == nil {
		log.Printf("User %s's public key field is empty", *usr.GetPrincipalName())
		writeError(w, http.StatusNotFound, "User's Public Key Not Found", "Err-25-19")
		return
	}
	validatingPosixCert.Cert.Key = usrPubKey
	setPrincipalErr := validatingPosixCert.SetPrincipalName(*usr.GetPrincipalName())
	if setPrincipalErr != nil {
		log.Printf("Was unable to set principal name to certificate in CSR")
		writeError(w, http.StatusInternalServerError, "Was unable to set Principal name to certificate in CSR", "Err-25-20")
		return
	}

	if uidImpl, ok := usr.(user.UID); ok {
		uid := uidImpl.GetUID()
		setUIDErr := validatingPosixCert.SetUIDClaim(*uid)
		if setUIDErr != nil {
			log.Printf("Was unable to set UID to certificate in CSR")
			writeError(w, http.StatusInternalServerError, "Was unable to set UID to certificate in CSR", "Err-25-21")
			return
		}
	}

	if primaryGrpImpl, ok := usr.(user.UserPrimaryGroup); ok {
		primaryGrp := primaryGrpImpl.GetPrimaryGroup()
		setPrimaryGrpErr := validatingPosixCert.SetPrimaryGroupClaim(primaryGrp)
		if setPrimaryGrpErr != nil {
			log.Printf("Was unable to set primary group to certificate in CSR")
			writeError(w, http.StatusInternalServerError, "Was unable to set primary group to certificate in CSR", "Err-25-22")
			return
		}
	}

	if secGrpsImpl, ok := usr.(user.UserSecondaryGroups); ok {
		secGrps := secGrpsImpl.GetUserSecondaryGroups()
		setSecGrpsErr := validatingPosixCert.SetGroupsClaim(secGrps)
		if setSecGrpsErr != nil {
			log.Printf("Was unable to set secondary groups to certificate in CSR")
			writeError(w, http.StatusInternalServerError, "Was unable to set secondary groups to certificate in CSR", "Err-25-23")
			return
		}
	}

	if sudoClaimsImpl, ok := usr.(user.UserSudoClaims); ok {
		sudoClaims := sudoClaimsImpl.GetUserSudoClaims()
		setSudoClaimsErr := validatingPosixCert.SetSUDOClaims(sudoClaims)
		if setSudoClaimsErr != nil {
			log.Printf("Was unable to set sudo claims to certificate in CSR")
			writeError(w, http.StatusInternalServerError, "Was unable to set sudo claims to certificate in CSR", "Err-25-24")
			return
		}
	}

	if passwdHashImpl, ok := usr.(user.UserLatestPasswdHash); ok {
		passwdHash := passwdHashImpl.GetLatestPasswdHash()
		setPasswdHashErr := validatingPosixCert.SetLatestPasswdHash(*passwdHash)
		if setPasswdHashErr != nil {
			log.Printf("Was unable to set password hash to certificate in CSR")
			writeError(w, http.StatusInternalServerError, "Was unable to set password hash to certificate in CSR", "Err-25-25")
			return
		}
	}

	validatingPosixCert.Cert.ValidAfter = uint64(time.Now().Unix())
	validatingPosixCert.Cert.ValidBefore = uint64(time.Now().Unix()) + ca.DefaultCertValidityPeriodInSeconds
	validatingPosixCert.Cert.Extensions["permit-agent-forwarding"] = ""
	validatingPosixCert.Cert.Extensions["permit-X11-forwarding"] = ""
	validatingPosixCert.Cert.Extensions["permit-port-forwarding"] = ""
	validatingPosixCert.Cert.Extensions["permit-pty"] = ""
	validatingPosixCert.Cert.Extensions["permit-user-rc"] = ""

	csr := &ca.DefaultCSR{
		PublicKey:       &validatingPosixCert.Cert.Key,
		Principals:      validatingPosixCert.Cert.ValidPrincipals,
		CertType:        ssh.UserCert,
		CertExtensions:  validatingPosixCert.Cert.Extensions,
		CriticalOptions: map[string]string{},
		ValidAfter:      &validatingPosixCert.Cert.ValidAfter,
		ValidBefore:     &validatingPosixCert.Cert.ValidBefore,
	}

	signedCert, signErr := srv.CA.SignCert(csr)
	if signErr != nil {
		log.Printf("CA errored out in signing the CSR - %+v", signErr)
		writeError(w, http.StatusInternalServerError, "CA errored out in signing the CSR", "Err-25-26")
		return
	}
	putCertErr := sshPutter.PutSSHCertForUser(signedCert, usr)
	if putCertErr != nil {
		log.Printf("CA errored out in signing the CSR - %+v", signErr)
		writeError(w, http.StatusInternalServerError, "CA errored out in signing the CSR", "Err-25-27")
		return
	}

	signedCertPEM := ssh.MarshalAuthorizedKey(signedCert)

	if adminRequest {
		resultJSON, marshalErr := json.Marshal(&struct {
			Cert                string `json:"cert,omitempty"`
			UIDKey              string `json:"uidKey,omitempty"`
			PrimaryGroupKey     string `json:"primaryGroupKey,omitempty"`
			SecondaryGroupsKey  string `json:"secondaryGroupsKey,omitempty"`
			SudoClaimsKey       string `json:"sudoClaimsKey,omitempty"`
			LatestPasswdHashKey string `json:"latestPasswdHashKey,omitempty"`
		}{
			Cert:                string(signedCertPEM),
			UIDKey:              validatingPosixCert.UIDKey,
			PrimaryGroupKey:     validatingPosixCert.PrimaryGroupKey,
			SecondaryGroupsKey:  validatingPosixCert.SecondaryGroupsKey,
			SudoClaimsKey:       validatingPosixCert.SudoClaimsKey,
			LatestPasswdHashKey: validatingPosixCert.LatestPasswdHashKey,
		})
		if marshalErr != nil {
			log.Printf("Error occurred while marshalling certificate to json - %+v", marshalErr)
			writeError(w, http.StatusInternalServerError, "Error occurred while marshalling certificate to json", "Err-25-28")
			return
		}
		writeResponse(w, http.StatusOK, resultJSON)
		return
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		now := time.Now()
		year, month, day := now.Date()
		hrs, mins, secs := now.Clock()
		fileName := fmt.Sprintf("%s_%d%s%d%d%d%d", *usr.GetPrincipalName(), year, month.String(), day, hrs, mins, secs)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-cert.pub\"", fileName))
		w.WriteHeader(http.StatusOK)
		w.Write(signedCertPEM)
		return
	}

}

//for requests GET /swoossh/admin/Cert/User/Name/:xxx/list?size=yy&token=zz&order=prev fetches user certs
//for requests GET /swoossh/myCerts?size=yy&token=zz&order=prev fetches user certs
func DefaultHTTPServerGetCertsForUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {
	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-26-10")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-26-11")
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to request SSH certificates of this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-25-12")
		return
	}
	store := srv.Store
	getCertsForUser, ok := store.(storage.GetSSHCertsForUser)
	if !ok {
		log.Print("Store does not implement GetSSHCertsForUser interface, cannot fulfill request")
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-26-02")
		return
	}

	var principalName *string

	//if call was to Admin API -
	if val := strings.TrimPrefix(r.URL.Path, GetCertsForUserByPrimaryNameAdminPrefixPath); val != r.URL.Path {
		if name := strings.TrimSuffix(val, GetCertsForUserByPrimaryNameAdminSuffixPath); name != val {
			if !*authnzResult.IsAdmin() {
				log.Print("Caller is not admin")
				writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-26-13")
				return
			}

			if name == "" {
				log.Print("principalName not found in request")
				writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-26-14")
				return
			}
			principalName = &name
		} else {
			writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-26-15")
			return
		}
	} else { //Non-admin API routes
		usr, authenticationErr := authnzResult.AuthenticatedPrincipal()
		if authenticationErr != nil {
			log.Printf("Failed to ID the user, quitting.")
			writeError(w, http.StatusUnauthorized, "Unknown user", "Err-25-29")
			return
		}
		tmp := usr.GetPrincipalName()
		principalName = tmp
	}

	userFilter := &storage.DefaultStoreUserFilter{
		PricipalNameProjection: principalName,
	}

	var token *string
	tokenQ, ok := r.URL.Query()[GetCertsTokenQueryParamName]
	if !ok || len(tokenQ) < 1 {
		log.Printf("URL search param %s is missing", GetCertsTokenQueryParamName)
		token = nil
	} else if tokenQ[0] == "" {
		token = nil
	} else {
		token = &tokenQ[0]
	}

	var resultSize *int
	sizeQ, ok := r.URL.Query()[GetCertsSizeQueryParamName]
	if !ok || len(sizeQ) < 1 {
		log.Printf("URL search param %s is missing", GetCertsSizeQueryParamName)
		resultSize = &GetCertsDefaultResultSize
	} else if sizeQ[0] == "" {
		resultSize = &GetCertsDefaultResultSize
	} else {
		tmp, err := strconv.Atoi(sizeQ[0])
		if err != nil {
			log.Printf("URL search param %s could not be cast to int", GetCertsSizeQueryParamName)
			writeError(w, http.StatusBadRequest, "Invalid input parameter", "Err-26-04")
			return
		}
		resultSize = &tmp
	}

	var order *storage.DDBQueryOrder
	forward := storage.DDBQueryOrderForward
	reverse := storage.DDBQueryOrderReverse
	orderQ, ok := r.URL.Query()[GetCertsOrderQueryParamName]
	if !ok || len(orderQ) < 1 {
		log.Printf("URL search param %s is missing", GetCertsOrderQueryParamName)
		order = &forward
	} else if orderQ[0] == "" {
		order = &forward
	} else {
		switch orderQ[0] {
		case GetCertsOrderValueEnumForward:
			order = &forward
		case GetCertsOrderValueEnumPrevious:
			order = &reverse
		default:
			order = &forward
		}
	}

	filter := &storage.DefaultStoreSSHCertSearchFilter{
		UserFilter: userFilter,
		PageToken:  token,
		PageSize:   resultSize,
		Order:      order,
	}

	resp, getCertsErr := getCertsForUser.GetSSHCertsForUser(filter)
	if getCertsErr != nil {
		log.Printf("Get certs for user call to storage returned error for %s - %+v", *principalName, getCertsErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-26-05")
		return
	}

	results := make([]string, 0)
	var nextPageToken, prevPageToken string
	if resp != nil {
		certResults := resp.GetCertSearchResults()
		for _, result := range certResults {
			certPEM := ssh.MarshalAuthorizedKey(result.GetSSHCert())
			results = append(results, string(certPEM))
		}
		if defaultDDBSearchResp, ok := resp.(*storage.DefaultStoreSSHCertSearchResponse); ok {
			if defaultDDBSearchResp.NextPageToken != nil {
				nextPageToken = *defaultDDBSearchResp.NextPageToken
			}
			if defaultDDBSearchResp.PreviousPageToken != nil {
				prevPageToken = *defaultDDBSearchResp.PreviousPageToken
			}
		}
	}

	resultsJSON, marshalErr := json.Marshal(&struct {
		Certs         []string `json:"certs"`
		NextPageToken string   `json:"nextPageToken"`
		PrevPageToken string   `json:"prevPageToken"`
	}{
		Certs:         results,
		NextPageToken: nextPageToken,
		PrevPageToken: prevPageToken,
	})

	if marshalErr != nil {
		log.Printf("Error occurred while marshalling results to json - %+v", marshalErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-26-06")
		return
	}
	writeResponse(w, http.StatusOK, resultsJSON)

}
