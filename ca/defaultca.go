package ca

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"math/bits"

	"golang.org/x/crypto/ssh"
)

// DefaultCA is a default model implementation of the CA interface.
type DefaultCA struct {
	HostSigner           ssh.Signer
	UserSigner           ssh.Signer
	RefreshSigners       func(*DefaultCA) error
	HostCertsMaxValidity uint64
	UserCertsMaxValidity uint64
}

// RandomProvider implementation of the CA interface for DefaultCA
func (c *DefaultCA) RandomProvider() (io.Reader, error) {
	return DefaultCARandomProvider()
}

// RefreshKeys implementation of the CA interface for DefaultCA
func (c *DefaultCA) RefreshKeys() error {
	return DefaultCARefreshKeys(c)
}

// SignCert implementation of the CA interface for DefaultCA
func (c *DefaultCA) SignCert(csr CSR) (*ssh.Certificate, error) {
	return SignCert(c, csr)
}

// GetHostCertSigner implementation of the CA interface for DefaultCA
func (c *DefaultCA) GetHostCertSigner(CSR) (ssh.Signer, error) {
	return DefaultCAGetHostCertSigner(c)
}

// GetUserCertSigner implementation of the CA interface for DefaultCA
func (c *DefaultCA) GetUserCertSigner(CSR) (ssh.Signer, error) {
	return DefaultCAGetUserCertSigner(c)
}

// CertSerialGenerator implementation of the CA interface for DefaultCA
func (c *DefaultCA) CertSerialGenerator() func(CSR) (uint64, error) {
	return DefaultCACertSerialGenerator()
}

// GetCAMaxValidityForHostCertificates implementation for DefaultCA
func (c *DefaultCA) GetCAMaxValidityForHostCertificates() uint64 {
	return DefaultCAMaxValidityForCertificates(c.HostCertsMaxValidity)
}

// GetCAMaxValidityForUserCertificates implementation for DefaultCA
func (c *DefaultCA) GetCAMaxValidityForUserCertificates() uint64 {
	return DefaultCAMaxValidityForCertificates(c.UserCertsMaxValidity)
}

// DefaultCARefreshKeys is a helper implementation of RefreshKeys provided
// for the benefit of CA implementations modeled after DefaultCA using an alias type definition
func DefaultCARefreshKeys(c *DefaultCA) error {
	return c.RefreshSigners(c)
}

// DefaultCAGetHostCertSigner is a helper implementation of GetHostCertSigner provided
// for the benefit of CA implementations modeled after DefaultCA using an alias type definition
func DefaultCAGetHostCertSigner(c *DefaultCA) (ssh.Signer, error) {
	return c.HostSigner, nil
}

// DefaultCAGetUserCertSigner is a helper implementation of GetUserCertSigner provided
// for the benefit of CA implementations modeled after DefaultCA using an alias type definition
func DefaultCAGetUserCertSigner(c *DefaultCA) (ssh.Signer, error) {
	return c.UserSigner, nil
}

// DefaultCARandomProvider is a helper implementation of RandomProvider provided
// for the benefit of CA implementations modeled after DefaultCA using an alias type definition
func DefaultCARandomProvider() (io.Reader, error) {
	return rand.Reader, nil
}

// DefaultCACertSerialGenerator is a helper implementation of CertSerialGenerator provided
// for the benefit of CA implementations modeled after DefaultCA using an alias type definition
func DefaultCACertSerialGenerator() func(CSR) (uint64, error) {
	fn := func(csr CSR) (uint64, error) {
		randomInt, err := rand.Int(rand.Reader, big.NewInt(bits.UintSize))
		if err != nil {
			return 0, fmt.Errorf("Failed to generate a Serial number for the certificate")
		}
		return randomInt.Uint64(), nil
	}
	return fn
}

// DefaultCAMaxValidityForCertificates is a helper implementation of CAMaxValidityForCertificates provided
// for the benefit of CA implementations modeled after DefaultCA using an alias type definition
func DefaultCAMaxValidityForCertificates(seconds uint64) uint64 {
	return seconds
}
