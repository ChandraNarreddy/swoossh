package httpserver

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/ChandraNarreddy/swoossh/storage"
	"github.com/ChandraNarreddy/swoossh/user"
)

var (
	GetUserByIDPrefixPath                  = "/swoossh/admin/User/ID/"
	GetUserByPrimaryNamePrefixPath         = "/swoossh/admin/User/Name/"
	PutUserByIDPrefixPath                  = "/swoossh/admin/User/ID/"
	PutUserByPrimaryNamePrefixPath         = "/swoossh/admin/User/Name/"
	PutUserByIDPrefixPathNonAdmin          = "/swoossh/User/ID/"
	DeleteUserByPrincipalNamePrefixPath    = "/swoossh/admin/User/Name/"
	POSTNewUserpath                        = "/swoossh/admin/User"
	SearchUsersByPrimaryNameQueryParamName = "name"
	SearchUsersSizeQueryParamName          = "size"
	SearchUsersTokenQueryParamName         = "token"
	SearchUsersOrderQueryParamName         = "order"

	MAXUSERPAYLOADBODYSIZE            = 1048576
	SearchUsersDefaultResultSize      = 20
	SearchUsersOrderValueEnumForward  = "forw"
	SearchUsersOrderValueEnumPrevious = "prev"
)

// for requests GET /swoossh/admin/User/ID/:uuid or /swoossh/admin/User/Name/:principalName
func DefaultHTTPServerGetUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {
	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-01-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-01-98")
		return
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-01-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-01-96")
		return
	}

	store := srv.Store
	var principalName, uniqueIdentifier *string
	if val := strings.TrimPrefix(r.URL.Path, GetUserByPrimaryNamePrefixPath); val != r.URL.Path {
		principalName = &val
	} else if val := strings.TrimPrefix(r.URL.Path, GetUserByIDPrefixPath); val != r.URL.Path {
		uniqueIdentifier = &val
	} else {
		writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-01-00")
		return
	}
	if principalName == nil && uniqueIdentifier == nil {
		log.Print("Neither PrincipalName nor UniqueIdentifier found in request")
		writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-01-01")
		return
	}
	userFilter := &storage.DefaultStoreUserFilter{
		PricipalNameProjection:         principalName,
		UserUniqueIdentifierProjection: uniqueIdentifier,
	}
	user, getUserErr := store.GetUser(userFilter)
	if getUserErr != nil {
		log.Printf("Error while retrieving user with filter %+v - %+v", userFilter, getUserErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-01-02")
		return
	}
	if user == nil {
		log.Printf("No user found for the filter %+v", userFilter)
		writeError(w, http.StatusNotFound, "User Not Found", "Err-01-03")
		return
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		log.Printf("Error occurred while marshalling user data to json - %+v", err)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-01-04")
		return
	}
	writeResponse(w, http.StatusOK, userJSON)
}

// for requests PUT /swoossh/admin/User/Name/:principalName creates a new user
// for requests PUT /swoossh/admin/User/ID/:uuid attempts to update an existing user
func DefaultHTTPServerPutUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-02-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-02-98")
		return
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-02-97")
		return
	}
	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "User not authorized to call", "Err-02-11")
		return
	}
	store := srv.Store
	var principalName, uniqueIdentifier *string
	if val := strings.TrimPrefix(r.URL.Path, PutUserByPrimaryNamePrefixPath); val != r.URL.Path {
		principalName = &val
		if principalName == nil {
			log.Print("principalName not found in request")
			writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-02-01")
			return
		}
	} else if val := strings.TrimPrefix(r.URL.Path, PutUserByIDPrefixPath); val != r.URL.Path {
		uniqueIdentifier = &val
		if uniqueIdentifier == nil {
			log.Print("uniqueIdentifier not found in request")
			writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-02-02")
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-02-00")
		return
	}

	//limiting the request size here to MAXBODYSIZE
	r.Body = http.MaxBytesReader(w, r.Body, int64(MAXUSERPAYLOADBODYSIZE))
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	ddbUser := storage.DefaultDynamoDBStoreUser{
		DefaultPosixUser: &user.DefaultPosixUser{},
	}
	decodeErr := dec.Decode(&ddbUser)
	if decodeErr != nil {
		writeJSONDecodeError(w, decodeErr)
		return
	}

	//if the request is to create the user
	if principalName != nil {
		ddbUser.SetPrincipalName(principalName)
		createUserErr := store.CreateUser(ddbUser)
		if createUserErr != nil {
			log.Printf("Create user call to storage returned error for %s - %+v", *principalName, createUserErr)
			writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-02-03")
			return
		}
		writeResponse(w, http.StatusCreated, []byte("{\"desc\":\"user created\"}"))
		return
	}

	//if request is for update
	if uniqueIdentifier != nil {
		ddbUser.UserUniqueIdentifier = uniqueIdentifier
		updateUserErr := store.UpdateUser(ddbUser)
		if updateUserErr != nil {
			log.Printf("Update user call to storage returned error for %s - %+v", *uniqueIdentifier, updateUserErr)
			writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-02-04")
			return
		}
		writeResponse(w, http.StatusOK, []byte("{\"desc\":\"user updated\"}"))
		return
	}
}

// for requests PUT /swoossh/User/ID/:uuid attempts to update an existing user
// currently only supports updating the publickey and latestPasswdHash of the user
func DefaultHTTPServerPutUserHandlerNonAdmin(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-06-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-06-98")
		return
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-06-97")
		return
	}

	store := srv.Store
	if val := strings.TrimPrefix(r.URL.Path, PutUserByIDPrefixPathNonAdmin); val != r.URL.Path {
		//this is an edit request from normal user
		caller, authenticationErr := authnzResult.AuthenticatedPrincipal()
		if authenticationErr != nil {
			log.Printf("Caller authentication failed")
			writeError(w, http.StatusUnauthorized, "Caller unknown", "Err-06-96")
			return
		}
		if caller == nil {
			log.Printf("Caller could not be identified")
			writeError(w, http.StatusUnauthorized, "Caller could not be id'd", "Err-06-95")
			return
		}

		//call should be for the user's own UUID
		var uniqueIdentifier *string
		uniqueIdentifier = &val
		if uniqueIdentifier == nil {
			log.Print("uniqueIdentifier not found in request")
			writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-06-01")
			return
		}
		userUUIDFilter := &storage.DefaultStoreUserFilter{
			UserUniqueIdentifierProjection: uniqueIdentifier,
		}
		usr, getUserErr := store.GetUser(userUUIDFilter)
		if getUserErr != nil {
			log.Printf("Error while retrieving user with the caller filter %+v - %+v", userUUIDFilter, getUserErr)
			writeError(w, http.StatusInternalServerError, "Error while retrieving user matching requested criteria", "Err-06-02")
			return
		}
		if usr == nil {
			log.Printf("No user found for the filter %+v", userUUIDFilter)
			writeError(w, http.StatusBadRequest, "No user matching requested criteria", "Err-06-03")
			return
		}
		if *usr.GetPrincipalName() != *caller.GetPrincipalName() {
			log.Printf("User %s requesting update of user %s - Unauthorized!", *caller.GetPrincipalName(), *usr.GetPrincipalName())
			writeError(w, http.StatusUnauthorized, "Caller unauthorized to affect change on requested resource", "Err-06-04")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(MAXUSERPAYLOADBODYSIZE))
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		passedInUser := storage.DefaultDynamoDBStoreUser{
			DefaultPosixUser: &user.DefaultPosixUser{},
		}
		decodeErr := dec.Decode(&passedInUser)
		if decodeErr != nil {
			writeJSONDecodeError(w, decodeErr)
			return
		}

		//check if admin-only modifiable fields are present in the passed in user
		if passedInUser.PrincipalName != nil || passedInUser.UID != nil ||
			passedInUser.PrimaryGroup != nil || passedInUser.SecondaryGroups != nil ||
			passedInUser.SudoClaims != nil {
			log.Print("Update user call has attributes that are not supported for normal users")
			writeError(w, http.StatusUnauthorized, "Update user call has attributes that are not supported for normal users", "Err-06-05")
			return
		}

		//only publickey and latestPasswdHash attributes are allowed to be modified by the user themselves
		//for the remaining the request has to come to the admin api
		modUsr := usr.(storage.DefaultDynamoDBStoreUser)
		if passedInUser.PublicKey != nil {
			modUsr.PublicKey = passedInUser.PublicKey
		}
		if passedInUser.LatestPasswdHash != nil {
			modUsr.LatestPasswdHash = passedInUser.LatestPasswdHash
		}
		updateUserErr := store.UpdateUser(modUsr)
		if updateUserErr != nil {
			log.Printf("Update user call to storage returned error for %s - %+v", *uniqueIdentifier, updateUserErr)
			writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-06-07")
			return
		}
		writeResponse(w, http.StatusOK, []byte("{\"desc\":\"user updated\"}"))
		return
	} else {
		writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-06-00")
		return
	}
}

// for requests POST "/swoossh/admin/User"
func DefaultHTTPServerPostUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-03-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-03-98")
		return
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-03-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-03-96")
		return
	}

	//limiting the request size here to MAXBODYSIZE
	store := srv.Store
	r.Body = http.MaxBytesReader(w, r.Body, int64(MAXUSERPAYLOADBODYSIZE))
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	ddbUser := storage.DefaultDynamoDBStoreUser{
		DefaultPosixUser: &user.DefaultPosixUser{},
	}
	decodeErr := dec.Decode(&ddbUser)
	if decodeErr != nil {
		writeJSONDecodeError(w, decodeErr)
		return
	}

	//if the request is to create the user
	if ddbUser.GetPrincipalName() != nil {
		createUserErr := store.CreateUser(ddbUser)
		if createUserErr != nil {
			log.Printf("Create user call to storage returned error for %s - %+v", *ddbUser.GetPrincipalName(), createUserErr)
			writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-03-02")
			return
		}
		writeResponse(w, http.StatusCreated, []byte("{\"desc\":\"user created\"}"))
		return
	} else {
		log.Print("User Principal Name not found in request")
		writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-03-01")
		return
	}
}

// for requests DELETE /swoossh/admim/User/Name/:principalName deletes an existing user
func DefaultHTTPServerDeleteUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-04-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-04-98")
		return
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-04-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-04-96")
		return
	}

	store := srv.Store
	var principalName *string
	if val := strings.TrimPrefix(r.URL.Path, DeleteUserByPrincipalNamePrefixPath); val != r.URL.Path {
		principalName = &val
		if principalName == nil {
			log.Print("principalName not found in request")
			writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-04-01")
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-04-00")
		return
	}
	ddbUser := storage.DefaultDynamoDBStoreUser{
		DefaultPosixUser: &user.DefaultPosixUser{},
	}
	/*
		//limiting the request size here to MAXBODYSIZE
		r.Body = http.MaxBytesReader(w, r.Body, int64(MAXUSERPAYLOADBODYSIZE))
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		ddbUser := storage.DefaultDynamoDBStoreUser{
			DefaultPosixUser: &user.DefaultPosixUser{},
		}
		decodeErr := dec.Decode(&ddbUser)
		if decodeErr != nil {
			writeJSONDecodeError(w, decodeErr)
			return
		}
	*/

	ddbUser.SetPrincipalName(principalName)
	deleteUserErr := store.DeleteUser(ddbUser)
	if deleteUserErr != nil {
		log.Printf("Delete user call to storage returned error for %s - %+v", *principalName, deleteUserErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-04-02")
		return
	}
	writeResponse(w, http.StatusOK, []byte("{\"desc\":\"user deleted\"}"))
	return
}

//for requests GET /swoossh/admin/Users?name=xxx&size=yy&token=zz&order=prev searches for users
func DefaultHTTPServerSearchUsersHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-05-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-05-98")
		return
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-05-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-05-96")
		return
	}

	store := srv.Store
	searchUsers, ok := store.(storage.SearchUsers)
	if !ok {
		log.Print("Store does not implement SearchUsers interface, cannot fulfill request")
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-05-01")
		return
	}

	nameQ, ok := r.URL.Query()[SearchUsersByPrimaryNameQueryParamName]
	if !ok || len(nameQ) < 1 {
		log.Printf("URL search param %s is missing", SearchUsersByPrimaryNameQueryParamName)
		writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-05-02")
		return
	}

	var token *string
	tokenQ, ok := r.URL.Query()[SearchUsersTokenQueryParamName]
	if !ok || len(tokenQ) < 1 {
		log.Printf("URL search param %s is missing or empty", SearchUsersTokenQueryParamName)
		token = nil
	} else if tokenQ[0] == "" {
		token = nil
	} else {
		token = &tokenQ[0]
	}

	var resultSize *int
	sizeQ, ok := r.URL.Query()[SearchUsersSizeQueryParamName]
	if !ok || len(sizeQ) < 1 {
		log.Printf("URL search param %s is missing or empty", SearchUsersSizeQueryParamName)
		resultSize = &SearchUsersDefaultResultSize
	} else if sizeQ[0] == "" {
		resultSize = &SearchUsersDefaultResultSize
	} else {
		tmp, err := strconv.Atoi(sizeQ[0])
		if err != nil {
			log.Printf("URL search param %s could not be cast to int", SearchUsersSizeQueryParamName)
			writeError(w, http.StatusBadRequest, "Invalid input parameter", "Err-05-03")
			return
		}
		resultSize = &tmp
	}

	var order *storage.DDBQueryOrder
	forward := storage.DDBQueryOrderForward
	reverse := storage.DDBQueryOrderReverse
	orderQ, ok := r.URL.Query()[SearchUsersOrderQueryParamName]
	if !ok || len(orderQ) < 1 {
		log.Printf("URL search param %s is missing", SearchUsersOrderQueryParamName)
		order = &forward
	} else if orderQ[0] == "" {
		order = &forward
	} else {
		switch orderQ[0] {
		case SearchUsersOrderValueEnumForward:
			order = &forward
		case SearchUsersOrderValueEnumPrevious:
			order = &reverse
		default:
			order = &forward
		}
	}

	searchFilter := &storage.DefaultStoreUserSearchFilter{
		UserNameSearchProjection: &nameQ[0],
		PageToken:                token,
		PageSize:                 resultSize,
		Order:                    order,
	}

	resp, searchErr := searchUsers.SearchUsers(searchFilter)
	if searchErr != nil {
		log.Printf("Search users call to storage returned error for %s - %+v", nameQ[0], searchErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-05-04")
		return
	}
	userSearchResults := resp.GetUserSearchResults()
	if len(userSearchResults) == 0 {
		log.Printf("Search users call to storage returned no matching results for %s - %+v", nameQ[0], searchErr)
		writeError(w, http.StatusNotFound, "No matching records", "Err-05-05")
		return
	}

	results := make([]user.User, 0)
	for _, result := range userSearchResults {
		results = append(results, result.GetUser())
	}

	var nextPageToken, prevPageToken string
	if defaultDDBSearchResp, ok := resp.(*storage.DefaultStoreUserSearchResponse); ok {
		if defaultDDBSearchResp.NextPageToken != nil {
			nextPageToken = *defaultDDBSearchResp.NextPageToken
		}
		if defaultDDBSearchResp.PreviousPageToken != nil {
			prevPageToken = *defaultDDBSearchResp.PreviousPageToken
		}
	}

	resultsJSON, marshalErr := json.Marshal(&struct {
		Users         []user.User `json:"users"`
		NextPageToken string      `json:"nextPageToken"`
		PrevPageToken string      `json:"prevPageToken"`
	}{
		Users:         results,
		NextPageToken: nextPageToken,
		PrevPageToken: prevPageToken,
	})

	if marshalErr != nil {
		log.Printf("Error occurred while marshalling search results to json - %+v", marshalErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-05-06")
		return
	}
	writeResponse(w, http.StatusOK, resultsJSON)
}
