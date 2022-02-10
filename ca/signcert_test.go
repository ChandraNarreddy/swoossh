package ca

import (
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type testCA struct {
	rand           io.Reader
	randErr        error
	refreshKeysErr error
	hostSigner     ssh.Signer
	hostSignerErr  error
	userSigner     ssh.Signer
	userSignerErr  error
	serial         uint64
	serialErr      error
}

func (c *testCA) RandomProvider() (io.Reader, error) {
	return c.rand, c.randErr
}
func (c *testCA) RefreshKeys() error {
	return c.refreshKeysErr
}
func (c *testCA) SignCert(CSR) (*ssh.Certificate, error) {
	return nil, nil
}
func (c *testCA) GetHostCertSigner(CSR) (ssh.Signer, error) {
	return c.hostSigner, c.hostSignerErr
}
func (c *testCA) GetUserCertSigner(CSR) (ssh.Signer, error) {
	return c.userSigner, c.userSignerErr
}
func (c *testCA) CertSerialGenerator() func(CSR) (uint64, error) {
	return func(CSR) (uint64, error) {
		return c.serial, c.serialErr
	}
}
func (c *testCA) GetCAMaxValidityInSecondsForUserCertificates() uint64 {
	return uint64(5 * 60)
}
func (c *testCA) GetCAMaxValidityInSecondsForHostCertificates() uint64 {
	return uint64(5 * 60)
}

type testCSR struct {
	pubKey          *ssh.PublicKey
	principals      []string
	certType        uint32
	validBefore     uint64
	validAfter      uint64
	criticalOptions map[string]string
	extensions      map[string]string
}

func (c *testCSR) GetPubKey() *ssh.PublicKey {
	return c.pubKey
}
func (c *testCSR) SetPubkey(*ssh.PublicKey) {}
func (c *testCSR) GetPrincipals() []string {
	return c.principals
}
func (c *testCSR) SetPrincipals([]string) {}
func (c *testCSR) GetCertType() uint32 {
	return c.certType
}
func (c *testCSR) SetCertType(uint32) {}

func (c *testCSR) GetValidBefore() uint64 {
	return c.validBefore
}
func (c *testCSR) SetValidBefore(uint64) {}
func (c *testCSR) GetValidAfter() uint64 {
	return c.validAfter
}
func (c *testCSR) SetValidAfter(uint64) {}
func (c *testCSR) GetCriticalOptions() map[string]string {
	return c.criticalOptions
}
func (c *testCSR) SetCriticalOptions(map[string]string) {}
func (c *testCSR) GetExtensions() map[string]string {
	return c.extensions
}
func (c *testCSR) SetExtensions(map[string]string) {}

func TestSignCert(t *testing.T) {
	signer, _ := ssh.ParsePrivateKey([]byte(keyPEM))
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	//func SignCert(ca CA, csr CSR) (*ssh.Certificate, error)
	validCA := testCA{
		rand:           rand.Reader,
		randErr:        nil,
		refreshKeysErr: nil,
		hostSigner:     signer,
		hostSignerErr:  nil,
		userSigner:     signer,
		userSignerErr:  nil,
		serial:         uint64(1233),
		serialErr:      nil,
	}
	validCSR := testCSR{
		pubKey:          &pub,
		principals:      []string{"principal1", "key1"},
		certType:        ssh.UserCert,
		validBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
		validAfter:      uint64(time.Now().Add(-5 * time.Second).Unix()),
		criticalOptions: map[string]string{"option1": "critical1", "option2": "critical2"},
		extensions:      map[string]string{"ext1": "val1", "ext2": "val2"},
	}

	inValidCertTypeCSR := validCSR
	inValidCertTypeCSR.certType = 4
	_, e1 := SignCert(&validCA, &inValidCertTypeCSR)
	if e1 == nil {
		t.Errorf("SignCert did not raise error for invalid cert type in CSR")
	}

	signerErrCA := validCA
	signerErrCA.userSignerErr = errors.New("")
	_, e2 := SignCert(&signerErrCA, &validCSR)
	if e2 == nil {
		t.Errorf("SignCert did not raise error for signer error in CA")
	}

	serialErrCA := validCA
	serialErrCA.serialErr = errors.New("")
	_, e3 := SignCert(&serialErrCA, &validCSR)
	if e3 == nil {
		t.Errorf("SignCert did not raise error for serial error in CA")
	}

	randomErrCA := validCA
	randomErrCA.randErr = errors.New("")
	_, e4 := SignCert(&randomErrCA, &validCSR)
	if e4 == nil {
		t.Errorf("SignCert did not raise error for random error in CA")
	}

	validHostCSR := validCSR
	validHostCSR.certType = ssh.HostCert
	signedHstCert, e5 := SignCert(&validCA, &validHostCSR)
	if e5 != nil {
		t.Errorf("SignCert raised error for valid CA and Host CSR")
	}
	if signedHstCert.ValidAfter == validHostCSR.GetValidAfter() {
		t.Errorf("ValidAfter field of the signed certificate is not overridden.")
	}
	if signedHstCert.ValidBefore == validHostCSR.GetValidBefore() {
		t.Errorf("ValidBefore field of the signed certificate is not overridden.")
	}
	if !reflect.DeepEqual(signedHstCert.CriticalOptions, validHostCSR.GetCriticalOptions()) {
		t.Errorf("critical options of the signed certificate don't match those supplied by CSR")
	}
	if !reflect.DeepEqual(signedHstCert.Extensions, validHostCSR.GetExtensions()) {
		t.Errorf("extension of the signed certificate don't match those supplied by CSR")
	}
	if signedHstCert.Key != pub {
		t.Errorf("pub key in the signed certificate does not match with the key supplied")
	}
	if signedHstCert.KeyId != "principal1_key1" {
		t.Errorf("key ID of the signed certificate does not match expected value")
	}
}
