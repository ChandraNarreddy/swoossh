package ca

import (
	"time"

	"golang.org/x/crypto/ssh"
)

var DefaultCertValidityPeriodInSeconds = uint64(5 * 24 * 3600)

type DefaultCSR struct {
	PublicKey       *ssh.PublicKey
	Principals      []string
	CertType        uint32
	CertExtensions  map[string]string
	CriticalOptions map[string]string
	ValidAfter      *uint64
	ValidBefore     *uint64
}

func (c *DefaultCSR) GetPubKey() *ssh.PublicKey {
	return c.PublicKey
}
func (c *DefaultCSR) SetPubkey(key *ssh.PublicKey) {
	c.PublicKey = key
}
func (c *DefaultCSR) GetPrincipals() []string {
	return c.Principals
}
func (c *DefaultCSR) SetPrincipals(principals []string) {
	c.Principals = principals
}
func (c *DefaultCSR) GetCertType() uint32 {
	return c.CertType
}
func (c *DefaultCSR) SetCertType(certType uint32) {
	c.CertType = certType
}
func (c *DefaultCSR) GetExtensions() map[string]string {
	return c.CertExtensions
}
func (c *DefaultCSR) SetExtensions(extensions map[string]string) {
	c.CertExtensions = extensions
}
func (c *DefaultCSR) GetCriticalOptions() map[string]string {
	return c.CriticalOptions
}
func (c *DefaultCSR) SetCriticalOptions(options map[string]string) {
	c.CriticalOptions = options
}
func (c *DefaultCSR) GetValidBefore() uint64 {
	if c.ValidBefore == nil {
		return uint64(time.Now().Unix()) + DefaultCertValidityPeriodInSeconds
	}
	return *c.ValidBefore
}
func (c *DefaultCSR) SetValidBefore(validBefore uint64) {
	c.ValidBefore = &validBefore
}
func (c *DefaultCSR) GetValidAfter() uint64 {
	if c.ValidAfter == nil {
		return uint64(time.Now().Unix())
	}
	return *c.ValidAfter
}
func (c *DefaultCSR) SetValidAfter(validAfter uint64) {
	c.ValidAfter = &validAfter
}
