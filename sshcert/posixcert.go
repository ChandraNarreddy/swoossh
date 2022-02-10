package sshcert

import group "github.com/ChandraNarreddy/swoossh/group"

type GetLatestPasswdHash interface {
	GetLatestPasswdHash() (string, error)
	SetLatestPasswdHash(string) error
}

type GetSUDOClaim interface {
	GetSUDOClaims() ([]string, error)
	SetSUDOClaims([]string) error
}

type GetPosixGroupsClaim interface {
	GetGroupsClaim() ([]group.PosixGroup, error)
	SetGroupsClaim([]group.PosixGroup) error
}

type CertPosixAccount interface {
	Cert
	GetUIDClaim() (uint32, error)
	SetUIDClaim(uint32) error
	GetPrimaryGroupClaim() (group.PosixGroup, error)
	SetPrimaryGroupClaim(group.PosixGroup) error
}
