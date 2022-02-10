package user

import "github.com/ChandraNarreddy/swoossh/group"

type UID interface {
	GetUID() *uint32
	SetUID(*uint32)
}

type UserPrimaryGroup interface {
	GetPrimaryGroup() group.PosixGroup
	SetPrimaryGroup(group group.PosixGroup)
}

type UserSecondaryGroups interface {
	GetUserSecondaryGroups() []group.PosixGroup
	SetUserSecondaryGroups([]group.PosixGroup)
}

type UserLatestPasswdHash interface {
	GetLatestPasswdHash() *string
	SetLatestPasswdHash(*string)
}

type UserSudoClaims interface {
	GetUserSudoClaims() []string
	SetUserSudoClaims([]string)
}

type PosixUser interface {
	User
	UID
	UserPrimaryGroup
	UserSecondaryGroups
}
