package ca

import (
	"fmt"
	"io"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

// SignCert is a helper implementation of SignCert of CA interface provided
// for the benefit of any CA implementation
func SignCert(ca CA, csr CSR) (*ssh.Certificate, error) {

	var signer ssh.Signer
	var signerErr error
	certType := csr.GetCertType()
	switch certType {
	case ssh.UserCert:
		signer, signerErr = ca.GetUserCertSigner(csr)
	case ssh.HostCert:
		signer, signerErr = ca.GetHostCertSigner(csr)
	default:
		log.Print("CSR has an unrecognized Certificate Type. Quitting!")
		return nil, fmt.Errorf("CSR has an unrecognized Certificate Type. Quitting")
	}
	if signerErr != nil {
		log.Print("Failed obtaining the appropriate signer for the cert type requested. Quitting")
		return nil, fmt.Errorf("Failed obtaining the appropriate signer for the cert type requested. Quitting")
	}

	serial, serialErr := ca.CertSerialGenerator()(csr)
	if serialErr != nil {
		log.Print("Failed generating serial number for the certificate. Quitting!")
		return nil, fmt.Errorf("Failed generating serial number for the certificate. Quitting")
	}

	randomProvider, randomErr := ca.RandomProvider()
	if randomErr != nil {
		log.Print("Random Provider failed to return valid generator, Quitting!")
		return nil, fmt.Errorf("Random Provider failed to return valid generator, Quitting")
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(randomProvider, nonce); err != nil {
		log.Print("Nonce could not be generated, Quitting!")
		return nil, fmt.Errorf("Nonce could not be generated, Quitting")
	}

	var keyID string
	for i, v := range csr.GetPrincipals() {
		if i > 0 {
			keyID = keyID + "_" + v
		} else {
			keyID = v
		}
	}

	var validBefore, validAfter uint64
	if validity, ok := csr.(CSRValidity); ok {
		validBefore = validity.GetValidBefore()
		validAfter = validity.GetValidAfter()
	}
	now := uint64(time.Now().Unix())
	if validAfter < now {
		log.Print("Cert validity period in CSR begins before current time, resetting it to now")
		validAfter = now
	}
	if caMaxValidity, ok := ca.(CAMaxValidityForCertificates); ok {
		var maxValidity uint64
		switch certType {
		case ssh.UserCert:
			maxValidity = caMaxValidity.GetCAMaxValidityInSecondsForUserCertificates()
		case ssh.HostCert:
			maxValidity = caMaxValidity.GetCAMaxValidityInSecondsForHostCertificates()
		}
		maxValidBefore := now + maxValidity
		if validBefore > maxValidBefore {
			log.Printf("Cert validity expiry time in CSR exceeds max life set for CA, resetting it to %d", maxValidBefore)
			validBefore = maxValidBefore
		}
	}

	perms := &ssh.Permissions{}
	if criticalOptions, ok := csr.(CSRCriticalOptions); ok {
		perms.CriticalOptions = criticalOptions.GetCriticalOptions()
	}
	if extensions, ok := csr.(CSRExtensions); ok {
		perms.Extensions = extensions.GetExtensions()
	}

	cert := &ssh.Certificate{
		Nonce:           nonce,
		Key:             *csr.GetPubKey(),
		Serial:          serial,
		CertType:        certType,
		KeyId:           keyID,
		ValidPrincipals: csr.GetPrincipals(),
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Permissions:     *perms,
		Reserved:        make([]byte, 0),
	}
	if signErr := cert.SignCert(randomProvider, signer); signErr != nil {
		log.Printf("Failed to sign the certificate - %s", signErr.Error())
		return nil, fmt.Errorf("Failed to sign the certificate - %s", signErr.Error())
	}
	return cert, nil
}
