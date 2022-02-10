package sshcert

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

func UnmarshalCert(certType string, base64Cert string) (*ssh.Certificate, error) {
	authKeysCert := (certType + " " + base64Cert)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authKeysCert))
	if err != nil {
		log.Printf("Failed to parse certificate from PEM format - %+v", err)
		return nil, fmt.Errorf("Failed to parse certificate from PEM format - %+v", err)
	}
	pubKey, err := ssh.ParsePublicKey(pub.Marshal())
	if err != nil {
		log.Printf("Failed to parse cert from SSH wire format - %+v", err)
		return nil, fmt.Errorf("Failed to parse cert from SSH wire format - %+v", err)
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		log.Printf("Failed to cast provided cert to certificate")
		return nil, fmt.Errorf("Failed to cast provided cert to certificate")
	}
	return cert, nil
}
