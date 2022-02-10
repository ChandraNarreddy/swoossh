package httpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/storage"
	"github.com/ChandraNarreddy/swoossh/user"
	"golang.org/x/crypto/ssh"
)

type affirmativeAdminAuthHandler struct {
	principal          string
	uuid               string
	customAuthnzResult bool
}
type affirmativeAdminAuthnzResult struct {
	principal string
	uuid      string
}

func (c *affirmativeAdminAuthnzResult) AuthenticatedPrincipal() (user.User, error) {
	user := storage.DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr(c.uuid),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName: strPtr(c.principal),
		},
	}
	return user, nil
}
func (c *affirmativeAdminAuthnzResult) AuthorizationResult() (*bool, error) {
	yes := true
	return &yes, nil
}
func (c *affirmativeAdminAuthnzResult) IsAdmin() *bool {
	yes := true
	return &yes
}

func (c *affirmativeAdminAuthHandler) AuthorizationHandler(w http.ResponseWriter, r *http.Request, s storage.Store) (AuthnzResult, bool, error) {
	isAdmin := true
	if !c.customAuthnzResult {
		return &DefaultAuthnzResult{
			errorAscertainingPrincipal:     false,
			errorAscertainingAuthorization: false,
			isAdmin:                        &isAdmin,
		}, false, nil
	} else {
		return &affirmativeAdminAuthnzResult{
			principal: c.principal,
			uuid:      c.uuid,
		}, false, nil
	}

}

func TestDefaultHTTPServerGetGroupHandler(t *testing.T) {
	putGroup(t)
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/swoossh/admin/Group/Name/Grp1", nil)
	DefaultHTTPServerGetGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get group by Name handler responded with non-200 response for valid request")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	uuid := bodyJSON["data"]["uuid"].(string)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/Group/ID/"+uuid, nil)
	DefaultHTTPServerGetGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get group by ID handler responded with non-200 response for valid request")
	}
	bodyBytes, _ = io.ReadAll(w.Result().Body)
	json.Unmarshal(bodyBytes, &bodyJSON)
	gid := bodyJSON["data"]["gid"].(float64)
	if gid != 345 {
		t.Errorf("gid returned by get group by ID handler does not match up to expected value")
	}
}

func TestDefaultHTTPServerPutGroupHandler(t *testing.T) {
	//DefaultHTTPServerPutGroupHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with putting group")
		return
	}
	grpCreateInput := `{"gid": 12232}`
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/swoossh/admin/Group/Name/ninja_dev", strings.NewReader(grpCreateInput))
	DefaultHTTPServerPutGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 201 {
		t.Errorf("put group by Name handler responded with non-201 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/Group/Name/ninja_dev", nil)
	DefaultHTTPServerGetGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get group by Name handler responded with non-200 response for previously put group")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	uuid := bodyJSON["data"]["uuid"].(string)
	grpUpdateInput := `{"gid": 9883, "name": "not_ninja"}`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/swoossh/admin/Group/ID/"+uuid, strings.NewReader(grpUpdateInput))
	DefaultHTTPServerPutGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("put group by ID handler responded with non-200 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/Group/Name/not_ninja", nil)
	DefaultHTTPServerGetGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get group by Name handler responded with non-200 response for previously updated group")
	}
	bodyBytes, _ = io.ReadAll(w.Result().Body)
	json.Unmarshal(bodyBytes, &bodyJSON)
	gid := bodyJSON["data"]["gid"].(float64)
	if gid != 9883 {
		t.Errorf("gid returned by get group by ID handler does not match up to expected value")
	}
}

func TestDefaultHTTPServerPostGroupHandler(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with putting group")
		return
	}
	grpCreateInput := `{"gid": 1434, "name": "ajnin_dev"}`
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/swoossh/admin/Group", strings.NewReader(grpCreateInput))
	DefaultHTTPServerPostGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 201 {
		t.Errorf("post group handler responded with non-201 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/Group/Name/ajnin_dev", nil)
	DefaultHTTPServerGetGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get group by Name handler responded with non-200 response for previously posted group")
	}
}

func TestDefaultHTTPServerDeleteGroupHandler(t *testing.T) {
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/swoossh/admin/Group/Name/Grp1", nil)
	DefaultHTTPServerDeleteGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode == 200 {
		t.Errorf("delete group by Name handler responded with 200 response for non-existent group")
	}
	putGroup(t)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/swoossh/admin/Group/Name/Grp1", nil)
	DefaultHTTPServerDeleteGroupHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("delete group by Name handler responded with non-200 response for valid request")
	}
}

func TestDefaultHTTPServerSearchGroupsHandler(t *testing.T) {
	//DefaultHTTPServerSearchGroupsHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with putting group")
		return
	}
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/swoossh/admin/Groups?name=non-existing&size=10&token=&order=forw", nil)
	DefaultHTTPServerSearchGroupsHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("search groups responses with non-200 response for non-existent group")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	grps, _ := bodyJSON["data"]["groups"].([]interface{})
	if len(grps) != 0 {
		t.Errorf("search groups handler returned 1 or more results for non-existant group")
	}
	putGroup(t)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/Groups?name=Grp&size=10&token=&order=forw", nil)
	DefaultHTTPServerSearchGroupsHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("search groups responses with non-200 response for valid group")
	}
	bodyBytes, _ = io.ReadAll(w.Result().Body)
	json.Unmarshal(bodyBytes, &bodyJSON)
	grps, _ = bodyJSON["data"]["groups"].([]interface{})
	if len(grps) != 1 {
		t.Errorf("search groups handler returned non matching results")
	}
}

func putGroup(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with putting group")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client
	grp := storage.DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g1"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(345),
			Name: strPtr("Grp1"),
		},
	}
	if e := storage.DefaultDynamoDBStoreCreateGroup(grp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}

	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	secGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(345),
		Name: strPtr("Grp1"),
	}
	secGrps := []group.PosixGroup{
		secGrp,
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
	if e := storage.DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}
}
