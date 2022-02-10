package storage

import (
	"github.com/ChandraNarreddy/swoossh/user"
	"golang.org/x/crypto/ssh"
)

type SSHCertSearchFilter interface {
}

type SSHCertSearchResult interface {
	GetSSHCert() *ssh.Certificate
}

type SSHCertSearchResp interface {
	GetCertSearchResults() []SSHCertSearchResult
}

type GetSSHCertsForUser interface {
	GetSSHCertsForUser(filter SSHCertSearchFilter) (SSHCertSearchResp, error)
}

type PutSSHCert interface {
	PutSSHCertForUser(*ssh.Certificate, user.User) error
}

type SSHCertStore interface {
}
