package httpserver

import (
	"net/http"

	"github.com/ChandraNarreddy/swoossh/storage"
	"github.com/ChandraNarreddy/swoossh/user"
)

type SearchUsersHandler interface {
	SearchUsersHandler(w http.ResponseWriter, r *http.Request)
}

type SearchGroupsHandler interface {
	SearchGroupsHandler(w http.ResponseWriter, r *http.Request)
}

type GetCertsForUserHandler interface {
	GetCertsForUserHandler(w http.ResponseWriter, r *http.Request)
}

type UsersHandler interface {
	GetUserHandler(w http.ResponseWriter, r *http.Request)
	PutUserHandler(w http.ResponseWriter, r *http.Request)
	PostUserHandler(w http.ResponseWriter, r *http.Request)
	DeleteUserHandler(w http.ResponseWriter, r *http.Request)
}

type GroupsHandler interface {
	GetGroupHandler(w http.ResponseWriter, r *http.Request)
	PutGroupHandler(w http.ResponseWriter, r *http.Request)
	PostGroupHandler(w http.ResponseWriter, r *http.Request)
	DeleteGroupHandler(w http.ResponseWriter, r *http.Request)
}

type SSHCertHandler interface {
	CreateSSHUserCertHandler(w http.ResponseWriter, r *http.Request)
}

type AuthnzResult interface {
	AuthenticatedPrincipal() (user.User, error)
	AuthorizationResult() (*bool, error)
	IsAdmin() *bool
}

type AuthorizationHandler interface {
	AuthorizationHandler(w http.ResponseWriter, r *http.Request, store storage.Store) (authnzResult AuthnzResult, requestFulfilled bool, err error)
}

type HTTPServer interface {
	UsersHandler
	GroupsHandler
	SSHCertHandler
	AuthorizationHandler
}
