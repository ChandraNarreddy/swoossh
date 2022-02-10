package ca

import (
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

var keyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS1CjjPe6sc0375DuAKpU84yhFX4qWM
rvfr3fuhg4yoTsK7G8tc5ryO7I/azKBuo5ICThSqQkbnPqzp9ojclsP5AAAAwEzr071M69
O9AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO
4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/
kAAAAgXT6Abfcw/mi4sNJPudZzHnHZyCvvrGFkeTnSK9F9ZkMAAAAjY2hhbmRyYWthbnRo
cmVkZHlATWFjQm9vay1Qcm8ubG9jYWwBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`

func ptrStr(a string) *string {
	return &a
}

type testSecretsManagerSvc struct {
	secretsmanageriface.SecretsManagerAPI
	secretValueOutput secretsmanager.GetSecretValueOutput
	secretValueError  error
}

func (c *testSecretsManagerSvc) GetSecretValue(*secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	output := c.secretValueOutput
	return &output, c.secretValueError
}

func TestNewAWSDefaultCA(t *testing.T) {
	validSecretManagerSvc := &testSecretsManagerSvc{
		secretValueOutput: secretsmanager.GetSecretValueOutput{
			SecretString: ptrStr(keyPEM),
		},
		secretValueError: nil,
	}
	_, e1 := NewAWSDefaultCA("", validSecretManagerSvc,
		"", validSecretManagerSvc, 10, 30)
	if e1 != nil {
		t.Errorf("NewAWSDefaultCA returned error for valid input")
	}
	b := make([]byte, base64.StdEncoding.EncodedLen(len(keyPEM)))
	base64.StdEncoding.Encode(b, []byte(keyPEM))
	validBinarySecretManagerSvc := &testSecretsManagerSvc{
		secretValueOutput: secretsmanager.GetSecretValueOutput{
			SecretBinary: b,
		},
		secretValueError: nil,
	}
	ca2, e2 := NewAWSDefaultCA("", validBinarySecretManagerSvc,
		"", validSecretManagerSvc, 10, 30)
	if e2 != nil {
		t.Errorf("NewAWSDefaultCA returned error for valid input")
	}
	e3 := ca2.RefreshKeys()
	if e3 != nil {
		t.Errorf("RefreshKeys returned error for valid AWSDefaultCA")
	}
}
