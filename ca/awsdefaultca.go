package ca

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"golang.org/x/crypto/ssh"
)

// NewAWSDefaultCA is a helper func to bootstrap a DefaultCA with CA keys fetched
// from AWS' secrets manager service.
// Requires secret paths for the host cert & user cert signer keys as parameters
// Requires max certificate validity duration as number of seconds
// Requires AWS Regions for each of the secrets
// Requires an AWS session with the appropriate region and credentials to fetch
// secrets which if nil, the func will try to create one using default configuration
// made available by the running environment.
func NewAWSDefaultCA(hostSignerKeyPEMSecretPath string,
	hostSignerKeySecretSvc secretsmanageriface.SecretsManagerAPI,
	userSignerKeyPEMSecretPath string,
	userSignerKeySecretSvc secretsmanageriface.SecretsManagerAPI,
	maxHostCertsValidityDays int,
	maxUserCertsValidityDays int) (*DefaultCA, error) {

	//hostSecretSvc := secretsmanager.New(sess, aws.NewConfig().WithRegion(hostSignerKeyAWSRegion))
	hostSigner, hostSignerErr := setUpSigner(hostSignerKeyPEMSecretPath, hostSignerKeySecretSvc)
	if hostSignerErr != nil {
		log.Printf("Failed to setup Host Certificate Signer - %+v", hostSignerErr)
		return nil, fmt.Errorf("Failed to setup Host Certificate Signer - %+v", hostSignerErr)
	}

	//userSecretSvc := secretsmanager.New(sess, aws.NewConfig().WithRegion(userSignerKeyAWSRegion))
	userSigner, userSignerErr := setUpSigner(userSignerKeyPEMSecretPath, userSignerKeySecretSvc)
	if userSignerErr != nil {
		log.Printf("Failed to setup User Certificate Signer - %+v", userSignerErr)
		return nil, fmt.Errorf("Failed to setup User Certificate Signer - %+v", userSignerErr)
	}
	awsDefaultCA := &DefaultCA{
		HostSigner: hostSigner,
		UserSigner: userSigner,
	}
	refresher := func(ca *DefaultCA) error {
		var hostSignerRefreshErr, userSignerRefreshErr error
		ca.HostSigner, hostSignerRefreshErr = setUpSigner(hostSignerKeyPEMSecretPath, hostSignerKeySecretSvc)
		ca.UserSigner, userSignerRefreshErr = setUpSigner(userSignerKeyPEMSecretPath, userSignerKeySecretSvc)
		if hostSignerRefreshErr != nil || userSignerRefreshErr != nil {
			return fmt.Errorf("Refreshing of one or both the host and user signers failed")
		}
		return nil
	}
	awsDefaultCA.RefreshSigners = refresher
	awsDefaultCA.HostCertsMaxValidity = uint64(maxHostCertsValidityDays) * 24 * 3600
	awsDefaultCA.UserCertsMaxValidity = uint64(maxUserCertsValidityDays) * 24 * 3600
	return awsDefaultCA, nil
}

func setUpSigner(pemSecretsManagerPath string, svc secretsmanageriface.SecretsManagerAPI) (ssh.Signer, error) {
	if svc == nil {
		log.Print("SecretsManager Service client passed is nil, cannot setup signer")
		return nil, fmt.Errorf("SecretsManager Service client passed is nil, cannot setup signer")
	}
	keyPEM, err := fetchAWSSecret(pemSecretsManagerPath, svc)
	if err != nil {
		log.Printf("Failed to fetch secret with path %s", pemSecretsManagerPath)
		return nil, fmt.Errorf("Failed to fetch secret with path %s", pemSecretsManagerPath)
	}
	signer, signerErr := ssh.ParsePrivateKey([]byte(keyPEM))
	if signerErr != nil {
		log.Printf("Failed to setup certificate signer - %+v", signerErr)
		return nil, fmt.Errorf("Failed to setup certificate signer - %+v", signerErr)
	}
	return signer, nil
}

func fetchAWSSecret(path string, svc secretsmanageriface.SecretsManagerAPI) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(path),
		VersionStage: aws.String("AWSCURRENT"),
	}
	result, err := svc.GetSecretValue(input)
	if err != nil {
		log.Printf("Failed to obtain secret value for entry %s - %+v", path, err)
		return "", fmt.Errorf("Failed to obtain secret value for entry %s - %+v", path, err)
	}
	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			log.Print("Could not base64 decode the secret value")
			return "", fmt.Errorf("Could not base64 decode the secret value")
		}
		secretString = string(decodedBinarySecretBytes[:len])
	}
	return secretString, nil
}

func attemptAWSSession() (*session.Session, error) {
	return session.NewSession()
}
