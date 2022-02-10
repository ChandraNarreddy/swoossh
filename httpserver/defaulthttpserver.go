package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/ChandraNarreddy/swoossh/ca"
	"github.com/ChandraNarreddy/swoossh/storage"
)

type DefaultHTTPServer struct {
	Store             storage.Store
	CA                ca.CA
	AuthHandler       AuthorizationHandler
	TemplateFS        fs.FS
	AdminHomeTmplName *string
	HomeTmplName      *string
}

func (c *DefaultHTTPServer) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerGetUserHandler(w, r, c)
}
func (c *DefaultHTTPServer) PutUserHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerPutUserHandler(w, r, c)
}
func (c *DefaultHTTPServer) PutUserHandlerNonAdmin(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerPutUserHandlerNonAdmin(w, r, c)
}
func (c *DefaultHTTPServer) PostUserHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerPostUserHandler(w, r, c)
}
func (c *DefaultHTTPServer) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerDeleteUserHandler(w, r, c)
}
func (c *DefaultHTTPServer) SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerSearchUsersHandler(w, r, c)
}

func (c *DefaultHTTPServer) GetGroupHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerGetGroupHandler(w, r, c)
}
func (c *DefaultHTTPServer) PutGroupHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerPutGroupHandler(w, r, c)
}
func (c *DefaultHTTPServer) PostGroupHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerPostGroupHandler(w, r, c)
}
func (c *DefaultHTTPServer) DeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerDeleteGroupHandler(w, r, c)
}
func (c *DefaultHTTPServer) SearchGroupsHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerSearchGroupsHandler(w, r, c)
}

func (c *DefaultHTTPServer) CreateSSHUserCertHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerCreateSSHUserCertHandler(w, r, c)
}
func (c *DefaultHTTPServer) GetCertsForUserHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerGetCertsForUserHandler(w, r, c)
}

func (c *DefaultHTTPServer) AuthorizationHandler(w http.ResponseWriter, r *http.Request) (authzResult AuthnzResult, requestFulfilled bool, err error) {
	return c.AuthHandler.AuthorizationHandler(w, r, c.Store)
}

func (c *DefaultHTTPServer) HomeHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPServerHomeHandler(w, r, c)
}

func (c *DefaultHTTPServer) PasswdChangeHandler(w http.ResponseWriter, r *http.Request) {
	DefaultHTTPPasswdChangeHandler(w, r, c)
}

func writeError(w http.ResponseWriter, responseCode int, desc string, errCode string) {
	type err struct {
		Desc    string `json:"desc,omitempty"`
		ErrCode string `json:"code,omitempty"`
	}

	errorResponse := struct {
		Error err `json:"error,omitempty"`
	}{
		Error: err{
			Desc:    desc,
			ErrCode: errCode,
		},
	}
	resp, marshalError := json.Marshal(&errorResponse)
	if marshalError != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Error"))
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(responseCode)
	w.Write(resp)
}

func writeResponse(w http.ResponseWriter, responseCode int, jsonData []byte) {
	jsonResponse := fmt.Sprintf("{\"data\": %s}", string(jsonData))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(responseCode)
	w.Write([]byte(jsonResponse))
}

func writeJSONDecodeError(w http.ResponseWriter, err error) {
	var syntaxError *json.SyntaxError
	var unmarshalTypeError *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxError):
		msg := fmt.Sprintf("Request body contains badly-formed JSON (at position %d)", syntaxError.Offset)
		log.Print(msg)
		writeError(w, http.StatusBadRequest, msg, "Err-10-01")

	case errors.Is(err, io.ErrUnexpectedEOF):
		msg := fmt.Sprintf("Request body contains badly-formed JSON")
		log.Print(msg)
		writeError(w, http.StatusBadRequest, msg, "Err-10-02")

	case errors.As(err, &unmarshalTypeError):
		msg := fmt.Sprintf("Request body contains an invalid value for the %q field (at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)
		log.Print(msg)
		writeError(w, http.StatusBadRequest, msg, "Err-10-03")

	case strings.HasPrefix(err.Error(), "json: unknown field "):
		fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
		msg := fmt.Sprintf("Request body contains unknown field %s", fieldName)
		log.Print(msg)
		writeError(w, http.StatusBadRequest, msg, "Err-10-04")

	case errors.Is(err, io.EOF):
		msg := "Request body must not be empty"
		log.Print(msg)
		writeError(w, http.StatusBadRequest, msg, "Err-10-05")

	case err.Error() == "http: request body too large":
		msg := "Request body must not be larger than MAXLIMIT"
		log.Print(msg)
		writeError(w, http.StatusBadRequest, msg, "Err-10-06")

	default:
		log.Print(err.Error())
		writeError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "Err-10-07")
	}
}
