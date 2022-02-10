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

func TestDefaultHTTPServerGetUserHandler(t *testing.T) {
	//DefaultHTTPServerGetUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	putUser(t)
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/smith", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by Name handler responded with non-200 response for valid request")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	uuid := bodyJSON["data"]["uuid"].(string)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/ID/"+uuid, nil)
	DefaultHTTPServerGetUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by ID handler responded with non-200 response for valid request")
	}
	bodyBytes, _ = io.ReadAll(w.Result().Body)
	json.Unmarshal(bodyBytes, &bodyJSON)
	name := bodyJSON["data"]["principalName"].(string)
	if name != "smith" {
		t.Errorf("principalname returned by get user by ID handler does not match up to expected value")
	}
	uid := bodyJSON["data"]["uid"].(float64)
	if uid != 123 {
		t.Errorf("uid returned by get user by ID handler does not match up to expected value")
	}
	email := bodyJSON["data"]["email"].(string)
	if email != "email@email.com" {
		t.Errorf("email returned by get user by ID handler does not match up to expected value")
	}
	primGrpID := bodyJSON["data"]["primaryGroup"].(map[string]interface{})["gid"].(float64)
	if primGrpID != 123 {
		t.Errorf("primGrpID returned by get user by ID handler does not match up to expected value")
	}
	primGrpName := bodyJSON["data"]["primaryGroup"].(map[string]interface{})["name"].(string)
	if primGrpName != "pname" {
		t.Errorf("primGrpName returned by get user by ID handler does not match up to expected value")
	}
	latestPasswdHash := bodyJSON["data"]["latestPasswdHash"].(string)
	if latestPasswdHash != "$1" {
		t.Errorf("latestPasswdHash returned by get user by ID handler does not match up to expected value")
	}
	publicKey := bodyJSON["data"]["publicKey"].(string)
	if publicKey != "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n" {
		t.Errorf("publicKey returned by get user by ID handler does not match up to expected value")
	}
	secGrps := bodyJSON["data"]["secondaryGroups"].([]interface{})
	if len(secGrps) != 1 {
		t.Errorf("updated secondary grps count after user updated handler does not match up to expected value")
	}
	if secGrps[0].(map[string]interface{})["gid"].(float64) != 345 {
		t.Errorf("updated secondary group gid returned after user update does not match up to expected value")
	}
	if secGrps[0].(map[string]interface{})["name"].(string) != "Grp1" {
		t.Errorf("updated secondary group name returned after user update does not match up to expected value")
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/Nonexistant", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode == 200 {
		t.Errorf("get user by ID handler responded with 200 response for non-existant user")
	}
}

func TestDefaultHTTPServerPutUserHandler(t *testing.T) {
	//DefaultHTTPServerPutUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with putting group")
		return
	}
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

	usrPutInput := `{
    "email":"ninja@add.com",
    "principalName":"ninja",
    "uid":12209,
    "primaryGroup":{"gid":12209,"name":"ninja"},
    "latestPasswdHash":"$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1",
    "publicKey":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=",
    "secondaryGroups":[{"gid":345,"name":"Grp1"}]
  }`
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/swoossh/admin/User/Name/ninja", strings.NewReader(usrPutInput))
	DefaultHTTPServerPutUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 201 {
		t.Errorf("put user by Name handler responded with non-201 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/ninja", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by Name handler responded with non-200 response for previously put user")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	uuid := bodyJSON["data"]["uuid"].(string)

	updatedGrp := storage.DefaultDynamoDBStoreGroup{
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(898),
			Name: strPtr("Grp2"),
		},
	}
	if e := storage.DefaultDynamoDBStoreCreateGroup(updatedGrp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	usrUpdateInput := `{
    "email":"not-ninja@add.com",
    "principalName":"not-ninja",
    "uid":1022,
    "primaryGroup":{"gid":1022,"name":"not-ninja"},
    "latestPasswdHash":"changed",
    "publicKey":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1AFZhk0Om7OamGPyVA46dkTj42e4QV5dYrAES4pbxpCMZB1LmGC4L7V3CROsf8ek6ZK02XFIWgrIU0aVIr/EeDyj1bgemb12td8Ss1ZcrA8XGXzvd2A01sm3ucviiK3TLtaUgpbjJvSh1TPvjf50n1s4BdJ2oAQgJ4SWJHUEiW1fc09U9m/8uF33zwjccmtT3nUmQK0rI1kw4wbzRGzfZtZqI/dO3SeGUFgzvOVINA81VTTDo5ryq9UA13uhUC2Az5hel/KMJ3WJ9FTIXJS5+bPR1bXoAw4nWbu+URBWXYnsfw6h5rLERqH7FzYFs6wjSp4t+AtGhapriUMlQHmLEXgD2EL9kYmr/WLk+YOgz4+b3DKq3mAnk0ZUsU6HdZxX0V+/29Ov38ZKXouegncEBVoRfojE9T5ccCX3PiO25DkHah8fzNvXevK6YaeF3Yjd+zPQcdN8SkmDuUZM7WEeGoYr0mb9h45Iqio5jCLsRnAVedjNu0kedmSDjFd/R3zM=",
    "secondaryGroups":[{"gid":898,"name":"Grp2"}]
  }`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/swoossh/admin/User/ID/"+uuid, strings.NewReader(usrUpdateInput))
	DefaultHTTPServerPutUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("put user by ID handler responded with non-200 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/not-ninja", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by Name handler responded with non-200 response for previously updated user")
	}
	bodyBytes, _ = io.ReadAll(w.Result().Body)
	json.Unmarshal(bodyBytes, &bodyJSON)
	uid := bodyJSON["data"]["uid"].(float64)
	if uid != 1022 {
		t.Errorf("uid returned by get user by ID handler does not match up to expected value")
	}
	email := bodyJSON["data"]["email"].(string)
	if email != "not-ninja@add.com" {
		t.Errorf("email returned by get user by ID handler does not match up to expected value")
	}
	primGrpID := bodyJSON["data"]["primaryGroup"].(map[string]interface{})["gid"].(float64)
	if primGrpID != 1022 {
		t.Errorf("primGrpID returned by get user by ID handler does not match up to expected value")
	}
	primGrpName := bodyJSON["data"]["primaryGroup"].(map[string]interface{})["name"].(string)
	if primGrpName != "not-ninja" {
		t.Errorf("primGrpName returned by get user by ID handler does not match up to expected value")
	}
	latestPasswdHash := bodyJSON["data"]["latestPasswdHash"].(string)
	if latestPasswdHash != "changed" {
		t.Errorf("latestPasswdHash returned by get user by ID handler does not match up to expected value")
	}
	publicKey := bodyJSON["data"]["publicKey"].(string)
	if publicKey != "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1AFZhk0Om7OamGPyVA46dkTj42e4QV5dYrAES4pbxpCMZB1LmGC4L7V3CROsf8ek6ZK02XFIWgrIU0aVIr/EeDyj1bgemb12td8Ss1ZcrA8XGXzvd2A01sm3ucviiK3TLtaUgpbjJvSh1TPvjf50n1s4BdJ2oAQgJ4SWJHUEiW1fc09U9m/8uF33zwjccmtT3nUmQK0rI1kw4wbzRGzfZtZqI/dO3SeGUFgzvOVINA81VTTDo5ryq9UA13uhUC2Az5hel/KMJ3WJ9FTIXJS5+bPR1bXoAw4nWbu+URBWXYnsfw6h5rLERqH7FzYFs6wjSp4t+AtGhapriUMlQHmLEXgD2EL9kYmr/WLk+YOgz4+b3DKq3mAnk0ZUsU6HdZxX0V+/29Ov38ZKXouegncEBVoRfojE9T5ccCX3PiO25DkHah8fzNvXevK6YaeF3Yjd+zPQcdN8SkmDuUZM7WEeGoYr0mb9h45Iqio5jCLsRnAVedjNu0kedmSDjFd/R3zM=\n" {
		t.Errorf("publicKey returned by get user by ID handler does not match up to expected value")
	}
	secGrps := bodyJSON["data"]["secondaryGroups"].([]interface{})
	if len(secGrps) != 1 {
		t.Errorf("updated secondary grps count after user updated handler does not match up to expected value")
	}
	if secGrps[0].(map[string]interface{})["gid"].(float64) != 898 {
		t.Errorf("updated secondary group gid returned after user update does not match up to expected value")
	}
	if secGrps[0].(map[string]interface{})["name"].(string) != "Grp2" {
		t.Errorf("updated secondary group name returned after user update does not match up to expected value")
	}
}

type affirmativeNonAdminAuthHandler struct {
	principal string
	uuid      string
}
type affirmativeNonAdminAuthnzResult struct {
	principal string
	uuid      string
}

func (c *affirmativeNonAdminAuthnzResult) AuthenticatedPrincipal() (user.User, error) {
	user := storage.DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr(c.uuid),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName: strPtr(c.principal),
		},
	}
	return user, nil
}
func (c *affirmativeNonAdminAuthnzResult) AuthorizationResult() (*bool, error) {
	yes := true
	return &yes, nil
}
func (c *affirmativeNonAdminAuthnzResult) IsAdmin() *bool {
	no := false
	return &no
}

func (c *affirmativeNonAdminAuthHandler) AuthorizationHandler(w http.ResponseWriter, r *http.Request, s storage.Store) (AuthnzResult, bool, error) {
	return &affirmativeNonAdminAuthnzResult{
		principal: c.principal,
		uuid:      c.uuid,
	}, false, nil
}

func TestDefaultHTTPServerPutUserHandlerNonAdmin(t *testing.T) {
	//DefaultHTTPServerPutUserHandlerNonAdmin(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with putting group")
		return
	}
	usrPutInput := `{
    "email":"ninja@add.com",
    "principalName":"ninja",
    "uid":12209,
    "primaryGroup":{"gid":12209,"name":"ninja"},
    "latestPasswdHash":"$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1",
    "publicKey":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="
  }`
	genericAdminDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/swoossh/admin/User/Name/ninja", strings.NewReader(usrPutInput))
	DefaultHTTPServerPutUserHandler(w, r, genericAdminDefaultHTTPServer)
	if w.Result().StatusCode != 201 {
		t.Errorf("put user by Name handler responded with non-201 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/ninja", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericAdminDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by Name handler responded with non-200 response for previously put user")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	uuid := bodyJSON["data"]["uuid"].(string)

	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeNonAdminAuthHandler{principal: "ninja"},
	}
	usrUpdateInputNonAdmin := `{
    "latestPasswdHash":"Non-Admin-Changed",
    "publicKey":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1AFZhk0Om7OamGPyVA46dkTj42e4QV5dYrAES4pbxpCMZB1LmGC4L7V3CROsf8ek6ZK02XFIWgrIU0aVIr/EeDyj1bgemb12td8Ss1ZcrA8XGXzvd2A01sm3ucviiK3TLtaUgpbjJvSh1TPvjf50n1s4BdJ2oAQgJ4SWJHUEiW1fc09U9m/8uF33zwjccmtT3nUmQK0rI1kw4wbzRGzfZtZqI/dO3SeGUFgzvOVINA81VTTDo5ryq9UA13uhUC2Az5hel/KMJ3WJ9FTIXJS5+bPR1bXoAw4nWbu+URBWXYnsfw6h5rLERqH7FzYFs6wjSp4t+AtGhapriUMlQHmLEXgD2EL9kYmr/WLk+YOgz4+b3DKq3mAnk0ZUsU6HdZxX0V+/29Ov38ZKXouegncEBVoRfojE9T5ccCX3PiO25DkHah8fzNvXevK6YaeF3Yjd+zPQcdN8SkmDuUZM7WEeGoYr0mb9h45Iqio5jCLsRnAVedjNu0kedmSDjFd/R3zM="
  }`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/swoossh/User/ID/"+uuid, strings.NewReader(usrUpdateInputNonAdmin))
	DefaultHTTPServerPutUserHandlerNonAdmin(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("put user by ID handler responded with non-200 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/ninja", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericAdminDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by Name handler responded with non-200 response for previously put user")
	}
	bodyBytes, _ = io.ReadAll(w.Result().Body)
	json.Unmarshal(bodyBytes, &bodyJSON)
	latestPasswdHash := bodyJSON["data"]["latestPasswdHash"].(string)
	if latestPasswdHash != "Non-Admin-Changed" {
		t.Errorf("latestPasswdHash returned by get user by ID handler does not match up to expected value")
	}
	publicKey := bodyJSON["data"]["publicKey"].(string)
	if publicKey != "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1AFZhk0Om7OamGPyVA46dkTj42e4QV5dYrAES4pbxpCMZB1LmGC4L7V3CROsf8ek6ZK02XFIWgrIU0aVIr/EeDyj1bgemb12td8Ss1ZcrA8XGXzvd2A01sm3ucviiK3TLtaUgpbjJvSh1TPvjf50n1s4BdJ2oAQgJ4SWJHUEiW1fc09U9m/8uF33zwjccmtT3nUmQK0rI1kw4wbzRGzfZtZqI/dO3SeGUFgzvOVINA81VTTDo5ryq9UA13uhUC2Az5hel/KMJ3WJ9FTIXJS5+bPR1bXoAw4nWbu+URBWXYnsfw6h5rLERqH7FzYFs6wjSp4t+AtGhapriUMlQHmLEXgD2EL9kYmr/WLk+YOgz4+b3DKq3mAnk0ZUsU6HdZxX0V+/29Ov38ZKXouegncEBVoRfojE9T5ccCX3PiO25DkHah8fzNvXevK6YaeF3Yjd+zPQcdN8SkmDuUZM7WEeGoYr0mb9h45Iqio5jCLsRnAVedjNu0kedmSDjFd/R3zM=\n" {
		t.Errorf("publicKey returned by get user by ID handler does not match up to expected value")
	}
}

func TestDefaultHTTPServerPostUserHandler(t *testing.T) {
	//DefaultHTTPServerPostUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with putting group")
		return
	}
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

	usrPostInput := `{
    "email":"ninja@add.com",
    "principalName":"ninja",
    "uid":12209,
    "primaryGroup":{"gid":12209,"name":"ninja"},
    "latestPasswdHash":"$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1",
    "publicKey":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=",
    "secondaryGroups":[{"gid":345,"name":"Grp1"}]
  }`
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/swoossh/admin/User", strings.NewReader(usrPostInput))
	DefaultHTTPServerPostUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 201 {
		t.Errorf("post user handler responded with non-201 response for valid request")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/ninja", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("get user by Name handler responded with non-200 response for previously put user")
	}
}

func TestDefaultHTTPServerDeleteUserHandler(t *testing.T) {
	//DefaultHTTPServerDeleteUserHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	putUser(t)
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/swoossh/admin/User/Name/smith", nil)
	DefaultHTTPServerDeleteUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("delete user handler responded with non-200 response for previously put user")
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/swoossh/admin/User/Name/smith", nil)
	DefaultHTTPServerGetUserHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode == 200 {
		t.Errorf("get user by ID handler responded with 200 response for non-existant user")
	}
}

func TestDefaultHTTPServerSearchUsersHandler(t *testing.T) {
	//DefaultHTTPServerSearchUsersHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer)
	putUser(t)
	genericDefaultHTTPServer := &DefaultHTTPServer{
		Store:       ddbStore,
		CA:          &mockCA{},
		AuthHandler: &affirmativeAdminAuthHandler{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/swoossh/admin/Users?name=smi&size=10&token=&order=forw", nil)
	DefaultHTTPServerSearchUsersHandler(w, r, genericDefaultHTTPServer)
	if w.Result().StatusCode != 200 {
		t.Errorf("search user handler responded with non 200 response")
	}
	bodyBytes, _ := io.ReadAll(w.Result().Body)
	var bodyJSON map[string]map[string]interface{}
	json.Unmarshal(bodyBytes, &bodyJSON)
	name := bodyJSON["data"]["users"].([]interface{})[0].(map[string]interface{})["principalName"].(string)
	if name != "smith" {
		t.Errorf("search user handler returned user")
	}
}

func putUser(t *testing.T) {
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
