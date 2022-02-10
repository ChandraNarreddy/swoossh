package httpserver

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"

	"golang.org/x/crypto/ssh"

	"github.com/ChandraNarreddy/swoossh/storage"
)

//for GET /swoossh/ or /swoossh/home
func DefaultHTTPServerHomeHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {
	authResult, requestFulfilled, authErr := srv.AuthHandler.AuthorizationHandler(w, r, srv.Store)
	if requestFulfilled {
		return
	}
	if authErr != nil {
		log.Printf("Authorization Error - %+v", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown internal error", "Err-40-00")
		return
	}
	caller, authenticationErr := authResult.AuthenticatedPrincipal()
	if authenticationErr != nil {
		log.Printf("Caller authentication failed")
		writeError(w, http.StatusUnauthorized, "Caller unknown", "Err-40-01")
		return
	}
	if caller == nil {
		log.Printf("Caller could not be identified")
		writeError(w, http.StatusUnauthorized, "Caller could not be id'd", "Err-40-02")
		return
	}
	callerName := *caller.GetPrincipalName()

	var callerPubKey string
	if caller.GetPublicKey() != nil {
		callerPubKey = string(ssh.MarshalAuthorizedKey(caller.GetPublicKey()))
	}

	if srv.TemplateFS == nil {
		log.Printf("Template filesystem has not been defined, cannot serve home page")
		writeError(w, http.StatusNotFound, "Page not found ", "Err-40-04")
		return
	}

	var ddbStoreUser storage.DefaultDynamoDBStoreUser
	var ok bool
	if ddbStoreUser, ok = caller.(storage.DefaultDynamoDBStoreUser); !ok {
		log.Printf("Caller object is not of type DefaultDynamoDBStoreUser. Cannot continue")
		writeError(w, http.StatusInternalServerError, "Unable to fetch user properties", "Err-40-03")
		return
	}

	if *authResult.IsAdmin() {
		log.Printf("User %s logged in with Admin privileges. Loading admin view", callerName)
		if srv.AdminHomeTmplName != nil {
			var buf bytes.Buffer
			renderErr := renderAdminHomePage(callerName, callerPubKey,
				*ddbStoreUser.UserUniqueIdentifier, srv.TemplateFS,
				*srv.AdminHomeTmplName, &buf)
			if renderErr != nil {
				log.Printf("Admin home page template render failed - %+v", renderErr)
				writeError(w, http.StatusNotFound, "Page not found ", "Err-40-04")
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(buf.Bytes())
			return
		} else {
			log.Printf("Admin home page template has not been defined")
			writeError(w, http.StatusNotFound, "Page not found ", "Err-40-05")
			return
		}
	}
	log.Printf("User %s logged in. Loading normal user view", callerName)
	if srv.HomeTmplName != nil {
		var buf bytes.Buffer
		renderErr := renderNormalUserHomePage(callerName, callerPubKey,
			*ddbStoreUser.UserUniqueIdentifier, srv.TemplateFS,
			*srv.HomeTmplName, &buf)
		if renderErr != nil {
			log.Printf("Home page template render failed - %+v", renderErr)
			writeError(w, http.StatusNotFound, "Page not found ", "Err-40-06")
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
		return
	} else {
		log.Printf("Home page template has not been defined")
		writeError(w, http.StatusNotFound, "Page not found ", "Err-40-07")
		return
	}
}

//for POST /swoossh/changePasswd
func DefaultHTTPPasswdChangeHandler(w http.ResponseWriter, r *http.Request, srv *DefaultHTTPServer) {
	authResult, requestFulfilled, authErr := srv.AuthHandler.AuthorizationHandler(w, r, srv.Store)
	if requestFulfilled {
		return
	}
	if authErr != nil {
		log.Printf("Authorization Error - %+v", authErr)
		writeError(w, http.StatusInternalServerError, "Unknown internal error", "Err-43-00")
		return
	}
	caller, authenticationErr := authResult.AuthenticatedPrincipal()
	if authenticationErr != nil {
		log.Printf("Caller authentication failed")
		writeError(w, http.StatusUnauthorized, "Caller unknown", "Err-43-01")
		return
	}
	if caller == nil {
		log.Printf("Caller could not be identified")
		writeError(w, http.StatusUnauthorized, "Caller could not be id'd", "Err-43-02")
		return
	}

	var ddbStoreUser storage.DefaultDynamoDBStoreUser
	var ok bool
	if ddbStoreUser, ok = caller.(storage.DefaultDynamoDBStoreUser); !ok {
		log.Printf("Caller object is not of type DefaultDynamoDBStoreUser. Cannot continue")
		writeError(w, http.StatusInternalServerError, "Unable to fetch user properties", "Err-43-03")
		return
	}

	//limiting the request size here to MAXBODYSIZE
	r.Body = http.MaxBytesReader(w, r.Body, int64(MAXUSERPAYLOADBODYSIZE))
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	changePasswordPayload := struct {
		CurrentPassword string `json:"currentPassword,omitempty"`
		NewPassword     string `json:"newPassword,omitempty"`
		ConfirmPassword string `json:"confirmPassword,omitempty"`
	}{}
	decodeErr := dec.Decode(&changePasswordPayload)
	if decodeErr != nil {
		writeJSONDecodeError(w, decodeErr)
		return
	}
	if changePasswordPayload.CurrentPassword == "" ||
		changePasswordPayload.NewPassword == "" {
		log.Printf("One or both of the submitted password fields are empty")
		writeError(w, http.StatusBadRequest, "Password field cannot be empty", "Err-43-04")
		return
	}

	//validation for current password
	if ddbStoreUser.LatestPasswdHash != nil {
		if *ddbStoreUser.LatestPasswdHash != changePasswordPayload.CurrentPassword {
			log.Printf("Current password hash does not match with what is in record")
			writeError(w, http.StatusBadRequest, "Current password does not match", "Err-43-05")
			return
		}
	} else {
		log.Printf("Caller's previous password  hash is nil. Cannot compare!")
		writeError(w, http.StatusConflict, "Previous Password is not set", "Err-43-06")
		return
	}
	newPasswd := changePasswordPayload.NewPassword
	ddbStoreUser.LatestPasswdHash = &newPasswd

	updateUserErr := srv.Store.UpdateUser(ddbStoreUser)
	if updateUserErr != nil {
		log.Printf("Update user call to storage returned error for caller %+v", updateUserErr)
		writeError(w, http.StatusInternalServerError, "Unknown Internal Error", "Err-43-07")
		return
	}
	writeResponse(w, http.StatusOK, []byte("{\"desc\":\"password updated\"}"))
	return
}

func renderAdminHomePage(username string, sshpublickey string, uuid string,
	tmplFS fs.FS, tmplFileName string, w io.Writer) error {
	tmpl, parseErr := template.ParseFS(tmplFS, tmplFileName)
	if parseErr != nil {
		log.Printf("Failed to parse Admin Home Page template  - %+v", parseErr)
		return parseErr
	}
	user := struct {
		Username     string
		SSHPublicKey string
		UUID         string
	}{
		Username:     username,
		SSHPublicKey: sshpublickey,
		UUID:         uuid,
	}
	return tmpl.Execute(w, user)
}

func renderNormalUserHomePage(username string, sshpublickey string, uuid string,
	tmplFS fs.FS, tmplFileName string, w io.Writer) error {
	tmpl, parseErr := template.ParseFS(tmplFS, tmplFileName)
	if parseErr != nil {
		log.Printf("Failed to parse Home Page template - %+v", parseErr)
		return parseErr
	}
	user := struct {
		Username     string
		SSHPublicKey string
		UUID         string
	}{
		Username:     username,
		SSHPublicKey: sshpublickey,
		UUID:         uuid,
	}
	return tmpl.Execute(w, user)
}
