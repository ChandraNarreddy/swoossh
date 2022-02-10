package storage

type Store interface {
	SSHCertStore
	SSHUserStore
	SSHGroupStore
}
