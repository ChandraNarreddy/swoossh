package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func fetchAWSSecret(awsSession *session.Session, region string, secretPath string) ([]byte, error) {
	sm := secretsmanager.New(awsSession, aws.NewConfig().WithRegion(region))
	secretInput := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretPath),
		VersionStage: aws.String("AWSCURRENT"),
	}
	result, smErr := sm.GetSecretValue(secretInput)
	if smErr != nil {
		return nil, fmt.Errorf("Error retrieving secret from secrets manager - %+v", smErr.Error())
	}
	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			log.Print("Could not base64 decode the secret value")
			return nil, fmt.Errorf("Could not base64 decode the secret value")
		}
		secretString = string(decodedBinarySecretBytes[:len])
	}
	var secretEntry struct {
		Secret string `json:"secret"`
	}
	err := json.Unmarshal([]byte(secretString), &secretEntry)
	if err != nil {
		return nil, fmt.Errorf("Unmarshalling the secret from SM failed - %+v", err)
	}
	return []byte(secretEntry.Secret), nil
}
