package ca

import (
	"io"

	"golang.org/x/crypto/ssh"
)

// CAMaxValidityForCertificates is an interface that CA implementations can
// implement to set a max validity duration for certs signed by them
type CAMaxValidityForCertificates interface {
	GetCAMaxValidityInSecondsForUserCertificates() uint64
	GetCAMaxValidityInSecondsForHostCertificates() uint64
}

// CA interface is the de-facto interface for all CA implementations to follow
type CA interface {
	RandomProvider() (io.Reader, error)
	RefreshKeys() error
	SignCert(CSR) (*ssh.Certificate, error)
	GetHostCertSigner(CSR) (ssh.Signer, error)
	GetUserCertSigner(CSR) (ssh.Signer, error)
	CertSerialGenerator() func(CSR) (uint64, error)
}
