package storage

import (
	"github.com/ChandraNarreddy/swoossh/user"
)

type UserFilter interface {
}

type UserSearchResult interface {
	GetUser() user.User
}

type UserSearchResp interface {
	GetUserSearchResults() []UserSearchResult
}

type SearchUsers interface {
	SearchUsers(UserFilter) (UserSearchResp, error)
}

type SSHUserStore interface {
	CreateUser(user.User) error
	GetUser(UserFilter) (user.User, error)
	UpdateUser(user.User) error
	DeleteUser(user.User) error
}
