package ca

import "golang.org/x/crypto/ssh"

type CSRValidity interface {
	GetValidBefore() uint64
	SetValidBefore(uint64)
	GetValidAfter() uint64
	SetValidAfter(uint64)
}

type CSRCriticalOptions interface {
	GetCriticalOptions() map[string]string
	SetCriticalOptions(map[string]string)
}

type CSRExtensions interface {
	GetExtensions() map[string]string
	SetExtensions(map[string]string)
}

type CSR interface {
	GetPubKey() *ssh.PublicKey
	SetPubkey(*ssh.PublicKey)
	GetPrincipals() []string
	SetPrincipals([]string)
	GetCertType() uint32
	SetCertType(uint32)
}
