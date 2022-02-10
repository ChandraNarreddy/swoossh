package httpserver

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/storage"
)

var (
	GetGroupByIDPrefixPath           = "/swoossh/admin/Group/ID/"
	GetGroupByPrimaryNamePrefixPath  = "/swoossh/admin/Group/Name/"
	PutGroupByIDPrefixPath           = "/swoossh/admin/Group/ID/"
	PutGroupByPrimaryNamePrefixPath  = "/swoossh/admin/Group/Name/"
	DeleteGroupByNamePrefixPath      = "/swoossh/admin/Group/Name/"
	SearchGroupsByNameQueryParamName = "name"
	SearchGroupsTokenQueryParamName  = "token"
	SearchGroupsSizeQueryParamName   = "size"
	SearchGroupsOrderQueryParamName  = "order"

	MAXGROUPPAYLOADBODYSIZE            = 1048576
	SearchGroupsDefaultResultSize      = 20
	SearchGroupsOrderValueEnumForward  = "forw"
	SearchGroupsOrderValueEnumPrevious = "prev"
)

// for requests GET /swoossh/admin/Group/ID/:uuid or /swoossh/admin/Group/Name/:groupname
func DefaultHTTPServerGetGroupHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-11-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-11-98")
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-11-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-11-96")
		return
	}

	store := srv.Store
	var grpName, uniqueIdentifier *string
	if val := strings.TrimPrefix(r.URL.Path, GetGroupByPrimaryNamePrefixPath); val != r.URL.Path {
		grpName = &val
	} else if val := strings.TrimPrefix(r.URL.Path, GetGroupByIDPrefixPath); val != r.URL.Path {
		uniqueIdentifier = &val
	} else {
		writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-11-00")
		return
	}
	if grpName == nil && uniqueIdentifier == nil {
		log.Print("Neither groupName nor UniqueIdentifier found in request")
		writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-11-01")
		return
	}

	groupFilter := &storage.DefaultStoreGroupFilter{
		GroupNameProjection:             grpName,
		GroupUniqueIdentifierProjection: uniqueIdentifier,
	}
	grp, getGroupErr := store.GetGroup(groupFilter)
	if getGroupErr != nil {
		log.Printf("Failed to retrive group with filter %+v - #%v", groupFilter, getGroupErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-11-02")
		return
	}
	if grp == nil {
		log.Printf("No group found for the filter %+v", groupFilter)
		writeError(w, http.StatusNotFound, "Group Not Found", "Err-11-03")
		return
	}
	groupJSON, err := json.Marshal(grp)
	if err != nil {
		log.Printf("Error occurred while marshalling group data to json - %+v", err)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-11-04")
		return
	}
	writeResponse(w, http.StatusOK, groupJSON)
}

// for requests PUT /swoossh/admin/Group/Name/:groupName creates a new group
// for requests PUT /swoossh/admin/Group/ID/:uuid attempts to update an existing group
func DefaultHTTPServerPutGroupHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-12-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-12-98")
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-12-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-12-96")
		return
	}

	store := srv.Store
	var groupName, uniqueIdentifier *string
	if val := strings.TrimPrefix(r.URL.Path, PutGroupByPrimaryNamePrefixPath); val != r.URL.Path {
		groupName = &val
		if groupName == nil {
			log.Print("groupName not found in request")
			writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-12-01")
			return
		}
	} else if val := strings.TrimPrefix(r.URL.Path, PutGroupByIDPrefixPath); val != r.URL.Path {
		uniqueIdentifier = &val
		if uniqueIdentifier == nil {
			log.Print("uniqueIdentifier not found in request")
			writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-12-02")
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-12-00")
		return
	}

	//limiting the request size here to MAXBODYSIZE
	r.Body = http.MaxBytesReader(w, r.Body, int64(MAXGROUPPAYLOADBODYSIZE))
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	ddbGrp := storage.DefaultDynamoDBStoreGroup{
		DefaultPosixGroup: &group.DefaultPosixGroup{},
	}
	decodeErr := dec.Decode(&ddbGrp)
	if decodeErr != nil {
		writeJSONDecodeError(w, decodeErr)
		return
	}

	//if the request is to create the group
	if groupName != nil {
		ddbGrp.SetGroupsName(groupName)
		createGroupErr := store.CreateGroup(ddbGrp)
		if createGroupErr != nil {
			log.Printf("Create group call to storage returned error for %s - %+v", *groupName, createGroupErr)
			writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-12-03")
			return
		}
		writeResponse(w, http.StatusCreated, []byte("{\"desc\":\"group created\"}"))
		return
	}

	//if request is for update
	if uniqueIdentifier != nil {
		ddbGrp.GroupUniqueIdentifier = uniqueIdentifier
		updateGroupErr := store.UpdateGroup(ddbGrp)
		if updateGroupErr != nil {
			log.Printf("Update group call to storage returned error for %s - %+v", *uniqueIdentifier, updateGroupErr)
			writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-12-04")
			return
		}
		writeResponse(w, http.StatusOK, []byte("{\"desc\":\"group updated\"}"))
		return
	}

}

// for requests POST /swoossh/admin/Group creates a new group
func DefaultHTTPServerPostGroupHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-13-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-13-98")
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-13-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-13-96")
		return
	}

	store := srv.Store
	//limiting the request size here to MAXBODYSIZE
	r.Body = http.MaxBytesReader(w, r.Body, int64(MAXGROUPPAYLOADBODYSIZE))
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	ddbGrp := storage.DefaultDynamoDBStoreGroup{
		DefaultPosixGroup: &group.DefaultPosixGroup{},
	}
	decodeErr := dec.Decode(&ddbGrp)
	if decodeErr != nil {
		writeJSONDecodeError(w, decodeErr)
		return
	}

	//if the request is to create the group
	if ddbGrp.GetGroupName() != nil {
		createGroupErr := store.CreateGroup(ddbGrp)
		if createGroupErr != nil {
			log.Printf("Create group call to storage returned error for %s - %+v", *ddbGrp.GetGroupName(), createGroupErr)
			writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-13-02")
			return
		}
		writeResponse(w, http.StatusCreated, []byte("{\"desc\":\"group created\"}"))
		return
	} else {
		log.Print("Group Name not found in request")
		writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-13-01")
		return
	}
}

// for requests DELETE /swoossh/admin/Group/Name/:groupName deletes an existing group
func DefaultHTTPServerDeleteGroupHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-14-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-14-98")
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-14-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-14-96")
		return
	}

	store := srv.Store
	var groupName *string
	if val := strings.TrimPrefix(r.URL.Path, DeleteGroupByNamePrefixPath); val != r.URL.Path {
		groupName = &val
		if groupName == nil {
			log.Print("groupName not found in request")
			writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-14-01")
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, "Incorrect routing", "Err-14-00")
		return
	}
	/*
		//limiting the request size here to MAXBODYSIZE
		r.Body = http.MaxBytesReader(w, r.Body, int64(MAXGROUPPAYLOADBODYSIZE))
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		ddbGrp := storage.DefaultDynamoDBStoreGroup{
			DefaultPosixGroup: &group.DefaultPosixGroup{},
		}
		decodeErr := dec.Decode(&ddbGrp)
		if decodeErr != nil {
			writeJSONDecodeError(w, decodeErr)
			return
		}
	*/
	ddbGrp := storage.DefaultDynamoDBStoreGroup{
		DefaultPosixGroup: &group.DefaultPosixGroup{},
	}
	ddbGrp.SetGroupsName(groupName)
	deleteGroupErr := store.DeleteGroup(ddbGrp)
	if deleteGroupErr != nil {
		log.Printf("Delete group call to storage returned error for %s - %+v", *groupName, deleteGroupErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-14-02")
		return
	}
	writeResponse(w, http.StatusOK, []byte("{\"desc\":\"group deleted\"}"))
	return
}

//for requests GET /swoossh/admin/Groups?name=xxx&size=yy&token=zz&order=prev searches for groups
func DefaultHTTPServerSearchGroupsHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {

	authnzResult, fulfilled, authErr := srv.AuthorizationHandler(w, r)
	if fulfilled {
		log.Printf("Authorization handler has fulfilled the request with error - %+v", authErr)
		return
	}
	if authErr != nil {
		log.Printf("AuthorizationHandler returned error %+v. Cannot proceed", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-15-99")
		return
	}
	authorized, authnzErr := authnzResult.AuthorizationResult()
	if authnzErr != nil {
		log.Printf("Unable to ascertain caller's authorization")
		writeError(w, http.StatusUnauthorized, "Unable to ascertain caller's authorization", "Err-15-98")
	}
	if authorized != nil && !*authorized {
		log.Printf("Caller not authorized to get this resource")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-15-97")
		return
	}

	if !*authnzResult.IsAdmin() {
		log.Print("Caller is not admin")
		writeError(w, http.StatusUnauthorized, "Caller unauthorized", "Err-15-96")
		return
	}

	store := srv.Store
	searchGroups, ok := store.(storage.SearchGroups)
	if !ok {
		log.Print("Store does not implement SearchGroups interface, cannot fulfill request")
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-15-01")
		return
	}

	nameQ, ok := r.URL.Query()[SearchGroupsByNameQueryParamName]
	if !ok || len(nameQ) < 1 {
		log.Printf("URL search param %s is missing", SearchGroupsByNameQueryParamName)
		writeError(w, http.StatusBadRequest, "Missing input parameters", "Err-15-02")
		return
	}

	var token *string
	tokenQ, ok := r.URL.Query()[SearchGroupsTokenQueryParamName]
	if !ok || len(tokenQ) < 1 {
		log.Printf("URL search param %s is missing", SearchGroupsTokenQueryParamName)
		token = nil
	} else if tokenQ[0] == "" {
		token = nil
	} else {
		token = &tokenQ[0]
	}

	var resultSize *int
	sizeQ, ok := r.URL.Query()[SearchGroupsSizeQueryParamName]
	if !ok || len(sizeQ) < 1 {
		log.Printf("URL search param %s is missing", SearchGroupsSizeQueryParamName)
		resultSize = &SearchGroupsDefaultResultSize
	} else if sizeQ[0] == "" {
		resultSize = &SearchGroupsDefaultResultSize
	} else {
		tmp, err := strconv.Atoi(sizeQ[0])
		if err != nil {
			log.Printf("URL search param %s could not be cast to int", SearchGroupsSizeQueryParamName)
			writeError(w, http.StatusBadRequest, "Invalid input parameter", "Err-15-03")
			return
		}
		resultSize = &tmp
	}

	var order *storage.DDBQueryOrder
	forward := storage.DDBQueryOrderForward
	reverse := storage.DDBQueryOrderReverse
	orderQ, ok := r.URL.Query()[SearchGroupsOrderQueryParamName]
	if !ok || len(orderQ) < 1 {
		log.Printf("URL search param %s is missing", SearchGroupsOrderQueryParamName)
		order = &forward
	} else if orderQ[0] == "" {
		order = &forward
	} else {
		switch orderQ[0] {
		case SearchGroupsOrderValueEnumForward:
			order = &forward
		case SearchGroupsOrderValueEnumPrevious:
			order = &reverse
		default:
			order = &forward
		}
	}

	searchFilter := &storage.DefaultStoreGroupSearchFilter{
		GroupNameSearchProjection: &nameQ[0],
		PageToken:                 token,
		PageSize:                  resultSize,
		Order:                     order,
	}

	resp, searchErr := searchGroups.SearchGroups(searchFilter)
	if searchErr != nil {
		log.Printf("Search groups call to storage returned error for %s - %+v", nameQ[0], searchErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-15-04")
		return
	}

	results := make([]group.Group, 0)
	groupSearchResults := resp.GetGroupSearchResults()
	for _, result := range groupSearchResults {
		results = append(results, result.GetGroup())
	}

	var nextPageToken, prevPageToken string
	if defaultDDBSearchResp, ok := resp.(*storage.DefaultStoreGroupSearchResponse); ok {
		if defaultDDBSearchResp.NextPageToken != nil {
			nextPageToken = *defaultDDBSearchResp.NextPageToken
		}
		if defaultDDBSearchResp.PreviousPageToken != nil {
			prevPageToken = *defaultDDBSearchResp.PreviousPageToken
		}
	}

	resultsJSON, marshalErr := json.Marshal(&struct {
		Groups        []group.Group `json:"groups"`
		NextPageToken string        `json:"nextPageToken"`
		PrevPageToken string        `json:"prevPageToken"`
	}{
		Groups:        results,
		NextPageToken: nextPageToken,
		PrevPageToken: prevPageToken,
	})

	if marshalErr != nil {
		log.Printf("Error occurred while marshalling search results to json - %+v", marshalErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-15-05")
		return
	}
	writeResponse(w, http.StatusOK, resultsJSON)
}
