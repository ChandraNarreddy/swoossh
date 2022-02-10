package authorizedprincipals

import (
	group "github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/sshcert"
)

type PosixHostUserAuthorize interface {
	PosixHostUserAuthorize(user string, cert sshcert.CertPosixAccount) (bool, error)
}

type PosixHostResetPasswd interface {
	PosixHostResetPasswd(user string, passwdHash string) error
}

type PosixHostCreateGroupIfNotExists interface {
	PosixHostCreateGroupIfNotExists(group.PosixGroup) error
}

type PosixHostOSExec interface {
	PosixHostOSExec(stdInput []byte, cmdAndArgs ...string) (string, error)
}

type PosixHostOwnershipEntitlements interface {
	PosixHostOwnershipEntitlements() []string
}

type PosixHostOwnershipEntitlementsKey interface {
	PosixHostOwnershipEntitlementsKey() string
}

type PosixHost interface {
	Host
}
