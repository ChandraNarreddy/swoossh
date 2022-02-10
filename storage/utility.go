package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/service/dynamodb"
)

func decodePageToken(token string) (map[string]*dynamodb.AttributeValue, error) {
	base64decodedToken, base64decodeErr := base64.URLEncoding.DecodeString(token)
	if base64decodeErr != nil {
		log.Printf("Error base64 decoding the page token %+v", base64decodeErr)
		return nil, fmt.Errorf("Error base64 decoding the page token %+v", base64decodeErr)
	}
	buf := bytes.NewBuffer(base64decodedToken)
	dec := gob.NewDecoder(buf)
	m := make(map[string]*dynamodb.AttributeValue)
	if decodeErr := dec.Decode(&m); decodeErr != nil {
		log.Printf("Error decoding the page token to a valid LastEvaluatedKey %+v", decodeErr)
		return nil, fmt.Errorf("Error decoding the page token to a valid LastEvaluatedKey %+v", decodeErr)
	}
	return m, nil
}

func encodeLastEvaluatedKey(key map[string]*dynamodb.AttributeValue) (string, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if encodeErr := enc.Encode(key); encodeErr != nil {
		log.Printf("Error encoding the LastEvaluatedKey to a page token %+v", encodeErr)
		return "", fmt.Errorf("Error encoding the LastEvaluatedKey to a page token %+v", encodeErr)
	}
	return base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}
