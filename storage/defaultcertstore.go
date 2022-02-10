package storage

import (
	"fmt"
	"log"

	"time"

	"github.com/ChandraNarreddy/swoossh/user"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type DefaultStoreSSHCertSearchFilter struct {
	UserFilter *DefaultStoreUserFilter
	PageToken  *string
	PageSize   *int
	Order      *DDBQueryOrder
}

type DefaultDynamoDBStoreCert struct {
	CertUniqueIdentifier *string
	*ssh.Certificate
}

func (c *DefaultDynamoDBStoreCert) GetSSHCert() *ssh.Certificate {
	return c.Certificate
}

type DefaultStoreSSHCertSearchResponse struct {
	Result            []*DefaultDynamoDBStoreCert
	NextPageToken     *string
	PreviousPageToken *string
}

func (c *DefaultStoreSSHCertSearchResponse) GetCertSearchResults() []SSHCertSearchResult {
	if len(c.Result) == 0 {
		return nil
	}
	result := make([]SSHCertSearchResult, 0)
	for _, each := range c.Result {
		result = append(result, each)
	}
	return result
}

func DefaultDynamoDBStoreGetSSHCertsForUser(filter SSHCertSearchFilter, store *DefaultDynamoDBStore) (SSHCertSearchResp, error) {
	certFilter, ok := filter.(*DefaultStoreSSHCertSearchFilter)
	if !ok {
		log.Print("The filter passed could not be cast to the supported filter type")
		return nil, fmt.Errorf("The filter passed could not be cast to the supported filter type")
	}
	user, getUserErr := store.GetUser(certFilter.UserFilter)
	if getUserErr != nil {
		log.Printf("Errored out while fetching user for filter %+v", *certFilter.UserFilter)
		return nil, fmt.Errorf("Errored out while fetching user for filter %+v", *certFilter.UserFilter)
	}
	if user == nil {
		log.Printf("No user found for filter %+v while fetching SSH Certs", *certFilter.UserFilter)
		return nil, fmt.Errorf("No user found for filter %+v while fetching SSH Certs", *certFilter.UserFilter)
	}
	nowString := time.Now().UTC().Format(DDBISO8601DateTimeFormat)
	laterString := time.Now().AddDate(1, 0, 0).UTC().Format(DDBISO8601DateTimeFormat)
	userCertificateCond := expression.KeyAnd(
		expression.Key(DDBRecordPK).Equal(expression.Value(DDBUserCertificateRecordPKPrefix+*user.GetPrincipalName())),
		expression.Key(DDBRecordSK).Between(expression.Value(DDBUserCertificateRecordSKPrefix+nowString),
			expression.Value(DDBUserCertificateRecordSKPrefix+laterString)),
	)
	userCertificateProj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordNameKey),
		expression.Name(DDBRecordUUIDKey),
		expression.Name(DDBRecordCreatedKey),
		expression.Name(DDBRecordTypeKey),
		expression.Name(DDBRecordPublicKeyKey),
		expression.Name(DDBRecordValidKey),
		expression.Name(DDBRecordCertificateKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(userCertificateCond).
		WithProjection(userCertificateProj).
		Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching user certificates for user record %s", *user.GetPrincipalName())
		return nil, fmt.Errorf("Failed to build DDB expression while fetching user certificates for user record %s", *user.GetPrincipalName())
	}

	certResults := make([]*DefaultDynamoDBStoreCert, 0)
	userCertsQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(*store.TableName),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}

	if certFilter.Order != nil {
		if *certFilter.Order == DDBQueryOrderReverse {
			fal := false
			userCertsQueryInput.ScanIndexForward = &fal
		}
	}

	var size *int64
	if certFilter.PageSize != nil {
		tmp := int64(*certFilter.PageSize)
		size = &tmp
	}

	var exclusiveStartKey, lastEvaluatedKey map[string]*dynamodb.AttributeValue
	if certFilter.PageToken != nil {
		var decodeTokenErr error
		exclusiveStartKey, decodeTokenErr = decodePageToken(*certFilter.PageToken)
		if decodeTokenErr != nil {
			log.Printf("Failure in decoding page token for user %s - %+v", *user.GetPrincipalName(), decodeTokenErr)
			return nil, fmt.Errorf("Failure in decoding page token for user %s", *user.GetPrincipalName())
		}
	}
	var firstEvaluatedKeyEncodedToken string
	for i := 0; ; {
		if size != nil {
			userCertsQueryInput.Limit = size
		}
		if exclusiveStartKey != nil {
			userCertsQueryInput.ExclusiveStartKey = exclusiveStartKey
		}
		userCertsQueryResult, userCertsQueryErr := store.DDBClient.Query(userCertsQueryInput)
		if userCertsQueryErr != nil {
			log.Printf("Error querying certificates for user %s - %+v", *user.GetPrincipalName(), userCertsQueryErr)
			return nil, fmt.Errorf("Error querying certificates for user %s", *user.GetPrincipalName())
		}
		if len(userCertsQueryResult.Items) > 0 {
			userCertItems := []Item{}
			if err := dynamodbattribute.UnmarshalListOfMaps(userCertsQueryResult.Items, &userCertItems); err != nil {
				log.Printf("Failed to unmarshall user certificate results for user %s - %+v", *user.GetPrincipalName(), err)
				continue
			}
			for _, item := range userCertItems {
				pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(item.Certificate))
				if err != nil {
					log.Printf("Failed to parse a cert for user %s - %+v", *user.GetPrincipalName(), err)
					continue
				}
				pubKey, err := ssh.ParsePublicKey(pub.Marshal())
				if err != nil {
					log.Printf("Failed to parse cert from SSH wire format for user %s- %+v", *user.GetPrincipalName(), err)
					continue
				}
				cert, ok := pubKey.(*ssh.Certificate)
				if !ok {
					log.Printf("Failed to cast cert to certificate for user %s", *user.GetPrincipalName())
					continue
				}
				defaultDynamoDBCert := DefaultDynamoDBStoreCert{
					CertUniqueIdentifier: &item.UUID,
					Certificate:          cert,
				}
				if certFilter.Order != nil {
					if *certFilter.Order == DDBQueryOrderReverse {
						certResults = append([]*DefaultDynamoDBStoreCert{&defaultDynamoDBCert}, certResults...)
					} else {
						certResults = append(certResults, &defaultDynamoDBCert)
					}
				} else {
					certResults = append(certResults, &defaultDynamoDBCert)
				}
			}
			if i == 0 {
				firstEvaluatedResult := Item{
					PK: userCertItems[0].PK,
					SK: userCertItems[0].SK,
				}
				firstEvaluatedResultItem, marshalErr := dynamodbattribute.MarshalMap(firstEvaluatedResult)
				if marshalErr != nil {
					log.Printf("Failed to marshal firstEvaluatedResult - %+v", marshalErr)
					return nil, fmt.Errorf("Failed to marshal firstEvaluatedResult - %+v", marshalErr)
				}
				var encodeErr error
				firstEvaluatedKeyEncodedToken, encodeErr = encodeLastEvaluatedKey(firstEvaluatedResultItem)
				if encodeErr != nil {
					log.Printf("Failed to encode first result item for key condition %+v - %+v", userCertificateCond, encodeErr)
					return nil, fmt.Errorf("Failed to encode first result item for key condition %+v", userCertificateCond)
				}
			}
		}
		if len(userCertsQueryResult.LastEvaluatedKey) != 0 {
			if int64(len(userCertsQueryResult.Items)) == *size {
				lastEvaluatedKey = userCertsQueryResult.LastEvaluatedKey
				break
			} else {
				tmp := *size - int64(len(userCertsQueryResult.Items))
				size = &tmp
				exclusiveStartKey = userCertsQueryResult.LastEvaluatedKey
			}
		} else {
			break
		}
	}
	if len(certResults) == 0 {
		log.Printf("No valid certificates found for user %s", *user.GetPrincipalName())
		resp := &DefaultStoreSSHCertSearchResponse{
			Result:            nil,
			NextPageToken:     nil,
			PreviousPageToken: nil,
		}
		return resp, nil
	}
	lastEvaluatedKeyEncodedToken, encodeErr := encodeLastEvaluatedKey(lastEvaluatedKey)
	if encodeErr != nil {
		log.Printf("Failed to encode lastEvaluatedKey for user %s cert results - %+v", *user.GetPrincipalName(), encodeErr)
		return nil, fmt.Errorf("Failed to encode lastEvaluatedKey for user %s cert results", *user.GetPrincipalName())
	}
	resp := &DefaultStoreSSHCertSearchResponse{
		Result:            certResults,
		NextPageToken:     &lastEvaluatedKeyEncodedToken,
		PreviousPageToken: &firstEvaluatedKeyEncodedToken,
	}

	if certFilter.Order != nil && *certFilter.Order == DDBQueryOrderReverse {
		resp.NextPageToken = &firstEvaluatedKeyEncodedToken
		resp.PreviousPageToken = &lastEvaluatedKeyEncodedToken
	}

	return resp, nil
}

func DefaultDynamoDBStorePutSSHCertForUser(cert *ssh.Certificate, user user.User, store *DefaultDynamoDBStore) error {
	userName := *user.GetPrincipalName()
	certExpiry := cert.ValidBefore
	certName := cert.KeyId
	uuid, uuidErr := uuid.NewRandom()
	if uuidErr != nil {
		log.Printf("Failed to generate uuid while putting cert for user %s", userName)
		return fmt.Errorf("Failed to generate uuid while putting cert for user %s", userName)
	}
	uuidStr := uuid.String()
	pubKey := ssh.MarshalAuthorizedKey(cert.Key)
	certPEM := ssh.MarshalAuthorizedKey(cert)
	certItem := Item{
		PK:          DDBUserCertificateRecordPKPrefix + userName,
		SK:          DDBUserCertificateRecordSKPrefix + time.Unix(int64(certExpiry), 0).Format(DDBISO8601DateTimeFormat),
		Name:        certName,
		UUID:        uuidStr,
		Created:     time.Now().UTC().Format(DDBISO8601DateTimeFormat),
		Type:        DDBRecordTypeUserCertEnum,
		PublicKey:   string(pubKey),
		Certificate: string(certPEM),
	}
	ddbTransactions := make([]*dynamodb.TransactWriteItem, 0)

	//condition check for user record existence
	userRecordPrimaryKey := map[string]string{
		DDBRecordPK: DDBUserRecordPKPrefix + userName,
		DDBRecordSK: DDBUserRecordSKPrefix + userName,
	}
	userPrimaryKey, err := dynamodbattribute.MarshalMap(userRecordPrimaryKey)
	if err != nil {
		log.Printf("Failed to marshal user's %s primary key attributes while checking its existence", userName)
		return fmt.Errorf("Failed to marshal user's %s primary key attributes while checking its existence", userName)
	}
	userExistsConditionExpression := fmt.Sprintf("attribute_exists(%s) and attribute_exists(%s)", DDBRecordPK, DDBRecordSK)
	userExistsConditionCheck := &dynamodb.ConditionCheck{
		Key:                 userPrimaryKey,
		TableName:           aws.String(*store.TableName),
		ConditionExpression: &userExistsConditionExpression,
	}
	userExistsConditionTransactionItem := &dynamodb.TransactWriteItem{
		ConditionCheck: userExistsConditionCheck,
	}
	ddbTransactions = append(ddbTransactions, userExistsConditionTransactionItem)

	//now for cert record addition
	putCertItem, marshalErr := dynamodbattribute.MarshalMap(certItem)
	if marshalErr != nil {
		log.Printf("Failed to marshal cert item for user %s", userName)
		return fmt.Errorf("Failed to marshal cert item for user %s", userName)
	}
	certPut := &dynamodb.Put{
		Item:      putCertItem,
		TableName: aws.String(*store.TableName),
	}
	putCertItemTransactionItem := &dynamodb.TransactWriteItem{
		Put: certPut,
	}
	ddbTransactions = append(ddbTransactions, putCertItemTransactionItem)

	certWriteTransactionInput := &dynamodb.TransactWriteItemsInput{
		TransactItems: ddbTransactions,
	}
	_, certWriteTransactionErr := store.DDBClient.TransactWriteItems(certWriteTransactionInput)
	if certWriteTransactionErr != nil {
		log.Printf("DynamoDB returned error while executing cert write transactions for %s - #%v", userName, certWriteTransactionErr)
		return fmt.Errorf("DynamoDB returned error while executing cert write transactions for %s", userName)
	}
	return nil
}
