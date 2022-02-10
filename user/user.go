package user

import "golang.org/x/crypto/ssh"

type User interface {
	GetPrincipalName() *string
	SetPrincipalName(*string)
	GetPublicKey() ssh.PublicKey
	SetPublicKey(pubkey ssh.PublicKey)
}
