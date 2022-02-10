package sshcert

type Cert interface {
	GetPrincipalName() (string, error)
	SetPrincipalName(string) error
}
