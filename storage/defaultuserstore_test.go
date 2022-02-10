package storage

import (
	"bytes"
	"encoding/json"
	"log"
	"reflect"
	"testing"

	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/user"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"golang.org/x/crypto/ssh"
)

var localDDBEndpoint = "http://localhost:8000"
var tableName = "CAStore"

var usrSearchOutputItems = []map[string]*dynamodb.AttributeValue{
	{
		DDBRecordPK:                         &dynamodb.AttributeValue{S: strPtr("user#1")},
		DDBRecordSK:                         &dynamodb.AttributeValue{S: strPtr("user#1")},
		DDBRecordNameKey:                    &dynamodb.AttributeValue{S: strPtr("one")},
		DDBRecordEmailKey:                   &dynamodb.AttributeValue{S: strPtr("one@one.com")},
		DDBRecordUUIDKey:                    &dynamodb.AttributeValue{S: strPtr("1")},
		DDBRecordTypeKey:                    &dynamodb.AttributeValue{S: strPtr("user")},
		DDBRecordPosixIdKey:                 &dynamodb.AttributeValue{S: strPtr("1")},
		DDBRecordUserPrimaryGroupKey:        &dynamodb.AttributeValue{S: strPtr("one")},
		DDBRecordPublicKeyKey:               &dynamodb.AttributeValue{S: strPtr("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=")},
		DDBRecordUserPrimaryGroupPosixIdKey: &dynamodb.AttributeValue{S: strPtr("1")},
		DDBRecordUserPasswordHashKey:        &dynamodb.AttributeValue{S: strPtr("$1")},
	},
	{
		DDBRecordPK:                         &dynamodb.AttributeValue{S: strPtr("user#2")},
		DDBRecordSK:                         &dynamodb.AttributeValue{S: strPtr("user#2")},
		DDBRecordNameKey:                    &dynamodb.AttributeValue{S: strPtr("two")},
		DDBRecordEmailKey:                   &dynamodb.AttributeValue{S: strPtr("two@two.com")},
		DDBRecordUUIDKey:                    &dynamodb.AttributeValue{S: strPtr("2")},
		DDBRecordTypeKey:                    &dynamodb.AttributeValue{S: strPtr("user")},
		DDBRecordPosixIdKey:                 &dynamodb.AttributeValue{S: strPtr("2")},
		DDBRecordUserPrimaryGroupKey:        &dynamodb.AttributeValue{S: strPtr("two")},
		DDBRecordPublicKeyKey:               &dynamodb.AttributeValue{S: strPtr("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=")},
		DDBRecordUserPrimaryGroupPosixIdKey: &dynamodb.AttributeValue{S: strPtr("2")},
		DDBRecordUserPasswordHashKey:        &dynamodb.AttributeValue{S: strPtr("$2")},
	},
	{
		DDBRecordPK:                         &dynamodb.AttributeValue{S: strPtr("user#3")},
		DDBRecordSK:                         &dynamodb.AttributeValue{S: strPtr("user#3")},
		DDBRecordNameKey:                    &dynamodb.AttributeValue{S: strPtr("three")},
		DDBRecordEmailKey:                   &dynamodb.AttributeValue{S: strPtr("three@three.com")},
		DDBRecordUUIDKey:                    &dynamodb.AttributeValue{S: strPtr("3")},
		DDBRecordTypeKey:                    &dynamodb.AttributeValue{S: strPtr("user")},
		DDBRecordPosixIdKey:                 &dynamodb.AttributeValue{S: strPtr("3")},
		DDBRecordUserPrimaryGroupKey:        &dynamodb.AttributeValue{S: strPtr("three")},
		DDBRecordPublicKeyKey:               &dynamodb.AttributeValue{S: strPtr("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=")},
		DDBRecordUserPrimaryGroupPosixIdKey: &dynamodb.AttributeValue{S: strPtr("3")},
		DDBRecordUserPasswordHashKey:        &dynamodb.AttributeValue{S: strPtr("$3")},
	},
}

var ddbStore = &DefaultDynamoDBStore{
	TableName:                  strPtr("CAStore"),
	GSIPosixIDIndexName:        strPtr("gsi_posix_id"),
	GSIUUIDIndexName:           strPtr("gsi_uuid"),
	GSISecondaryGroupIndexName: strPtr("gsi_secondary_group"),
	GSINameIndexName:           strPtr("gsi_name"),
	GSIEmailIndexName:          strPtr("gsi_email"),
	GSITypeIndexName:           strPtr("gsi_type"),
}

var forw = DDBQueryOrder(1)
var rev = DDBQueryOrder(2)

func strPtr(i string) *string {
	return &i
}

func intPtr(i int) *int {
	return &i
}

func uint16Ptr(i int) *uint16 {
	k := uint16(i)
	return &k
}

func uint32Ptr(i int) *uint32 {
	k := uint32(i)
	return &k
}

func localDDBClient() *dynamodb.DynamoDB {
	cfg := aws.Config{
		Endpoint:    aws.String(localDDBEndpoint),
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials("dummy", "dummy", ""),
	}
	sess := session.Must(session.NewSession(&cfg))
	return dynamodb.New(sess)
}

func cleanUpDB() error {
	client := localDDBClient()
	tableDeleteInput := &dynamodb.DeleteTableInput{
		TableName: aws.String(tableName),
	}
	log.Printf("Cleaning up the DB.")
	if _, err := client.DeleteTable(tableDeleteInput); err != nil {
		log.Printf("Got error calling delete table: %s", err)
		return err
	}
	tableCreateInput := &dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("pk"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("sk"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("name"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("uuid"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("type"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("posix_id"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("secondary_group"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("email"),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("pk"),
				KeyType:       aws.String("HASH"),
			},
			{
				AttributeName: aws.String("sk"),
				KeyType:       aws.String("RANGE"),
			},
		},
		GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
			{
				IndexName: aws.String("gsi_posix_id"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("posix_id"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("type"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_uuid"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("uuid"),
						KeyType:       aws.String("HASH"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_secondary_group"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("secondary_group"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("pk"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_name"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("name"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("type"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_email"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("email"),
						KeyType:       aws.String("HASH"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("gsi_type"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("type"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("pk"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
		},
		BillingMode: aws.String("PROVISIONED"),
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
		TableName: aws.String(tableName),
	}
	log.Printf("Adding table to the DB.")
	if _, err := client.CreateTable(tableCreateInput); err != nil {
		log.Printf("Got error calling create table: %s", err)
		return err
	}
	return nil
}

var queryOutput dynamodb.QueryOutput

type mockStoreDynamoDBClient struct {
	dynamodbiface.DynamoDBAPI
}

func (c mockStoreDynamoDBClient) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	return &queryOutput, nil
}

func TestDefaultStoreUserSearchResponseGetUserSearchResults(t *testing.T) {
	emptyResp := &DefaultStoreUserSearchResponse{}
	if emptyResp.GetUserSearchResults() != nil {
		t.Error("GetUserSearchResults is not null")
	}
	results := []*DefaultDynamoDBStoreUser{&DefaultDynamoDBStoreUser{}, &DefaultDynamoDBStoreUser{}}
	searchResp := &DefaultStoreUserSearchResponse{
		Result: results,
	}
	if searchResp.GetUserSearchResults() == nil {
		t.Error("GetUserSearchResults is null")
	}
}

func TestDefaultDynamoDBStoreSearchUsers(t *testing.T) {
	var temp interface{}
	if _, err := DefaultDynamoDBStoreSearchUsers(temp, &DefaultDynamoDBStore{}); err == nil {
		t.Error("UserSearchfilter check failed")
	}
	nilNameSearchFilter := &DefaultStoreUserSearchFilter{}
	if _, err := DefaultDynamoDBStoreSearchUsers(nilNameSearchFilter, &DefaultDynamoDBStore{}); err == nil {
		t.Error("Nil UserSearchfilter check failed")
	}
	queryOutput = dynamodb.QueryOutput{
		Items:            usrSearchOutputItems,
		LastEvaluatedKey: usrSearchOutputItems[2],
	}
	mockClient := &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	filter := &DefaultStoreUserSearchFilter{
		UserNameSearchProjection: strPtr(""),
		PageToken:                strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                 intPtr(3),
		Order:                    &forw,
	}
	resp, err := DefaultDynamoDBStoreSearchUsers(filter, ddbStore)
	if err != nil {
		t.Errorf("GetUserSearchResults returned error - %+v", err.Error())
	}
	if len(resp.GetUserSearchResults()) != len(usrSearchOutputItems) {
		t.Error("GetUserSearchResults length does not match with supplied output items")
	}
	if _, ok := resp.(*DefaultStoreUserSearchResponse); !ok {
		t.Error("GetUserSearchResults is not returning DefaultStoreUserSearchResponse")
	}

	queryOutput = dynamodb.QueryOutput{
		Items:            []map[string]*dynamodb.AttributeValue{},
		LastEvaluatedKey: nil,
	}
	mockClient = &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	filter = &DefaultStoreUserSearchFilter{
		UserNameSearchProjection: strPtr(""),
		PageToken:                strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                 intPtr(3),
		Order:                    &forw,
	}
	resp, err = DefaultDynamoDBStoreSearchUsers(filter, ddbStore)
	if err != nil {
		t.Errorf("GetUserSearchResults returned error - %+v", err.Error())
	}
	if len(resp.GetUserSearchResults()) != 0 {
		t.Error("GetUserSearchResults length is not zero for zero results")
	}

	queryOutput = dynamodb.QueryOutput{
		Items:            usrSearchOutputItems,
		LastEvaluatedKey: usrSearchOutputItems[2],
	}
	mockClient = &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	noOrderfilter := &DefaultStoreUserSearchFilter{
		UserNameSearchProjection: strPtr(""),
		PageToken:                strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                 intPtr(3),
	}
	resp, err = DefaultDynamoDBStoreSearchUsers(noOrderfilter, ddbStore)
	if err != nil {
		t.Errorf("GetUserSearchResults returned error - %+v", err.Error())
	}

	queryOutput = dynamodb.QueryOutput{
		Items:            usrSearchOutputItems,
		LastEvaluatedKey: usrSearchOutputItems[2],
	}
	mockClient = &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	revOrderfilter := &DefaultStoreUserSearchFilter{
		UserNameSearchProjection: strPtr(""),
		PageToken:                strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                 intPtr(6),
		Order:                    &rev,
	}
	resp, err = DefaultDynamoDBStoreSearchUsers(revOrderfilter, ddbStore)
	if err != nil {
		t.Errorf("GetUserSearchResults returned error - %+v", err.Error())
	}
}

func TestDefaultDynamoDBStoreCreateUser(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	grp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(345),
		Name: strPtr("secGrp1"),
	}
	secGrps := []group.PosixGroup{
		grp,
	}
	usr := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("smith"),
			UID:              uint32Ptr(123),
			PublicKey:        pub,
			PrimaryGroup:     primGrp,
			SecondaryGroups:  secGrps,
			LatestPasswdHash: strPtr("$1"),
			SudoClaims: []string{
				"smith locahost = /var/www/apache",
				"smith	locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	ddbSecGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("gpr"),
		DefaultPosixGroup:     grp,
	}
	if e := DefaultDynamoDBStoreCreateGroup(ddbSecGrp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	if e := DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}

	notDefaultDynamoDBStoreUser := &user.DefaultPosixUser{
		PrincipalName:   strPtr("smith"),
		UID:             uint32Ptr(321),
		PublicKey:       pub,
		PrimaryGroup:    primGrp,
		SecondaryGroups: secGrps,
	}
	if e := DefaultDynamoDBStoreCreateUser(notDefaultDynamoDBStoreUser, ddbStore); e == nil {
		t.Error("Error not raised when non-DefaultDynamoDBStoreUser is passed")
	}

	nilPrincipalUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			UID:             uint32Ptr(345),
			PublicKey:       pub,
			PrimaryGroup:    primGrp,
			SecondaryGroups: secGrps,
		},
	}
	if e := DefaultDynamoDBStoreCreateUser(nilPrincipalUser, ddbStore); e == nil {
		t.Error("Error not raised when nil principal user is passed")
	}

	nilEmailUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:   strPtr("smith"),
			UID:             uint32Ptr(543),
			PublicKey:       pub,
			PrimaryGroup:    primGrp,
			SecondaryGroups: secGrps,
		},
	}
	if e := DefaultDynamoDBStoreCreateUser(nilEmailUser, ddbStore); e == nil {
		t.Error("Error not raised when nil email user is passed")
	}

	nilUIDUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:   strPtr("smith"),
			PublicKey:       pub,
			PrimaryGroup:    primGrp,
			SecondaryGroups: secGrps,
		},
	}
	if e := DefaultDynamoDBStoreCreateUser(nilUIDUser, ddbStore); e == nil {
		t.Error("Error not raised when nil uid user is passed")
	}

	usedUIDUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:   strPtr("smith"),
			UID:             uint32Ptr(123),
			PublicKey:       pub,
			PrimaryGroup:    primGrp,
			SecondaryGroups: secGrps,
		},
	}
	if e := DefaultDynamoDBStoreCreateUser(usedUIDUser, ddbStore); e == nil {
		t.Error("Error not raised when used up uid user is passed")
	}

	noNameSecGrp := &group.DefaultPosixGroup{
		Gid: uint16Ptr(909),
	}
	noNameSecGrps := []group.PosixGroup{
		noNameSecGrp,
	}
	noNameSecGrpUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:   strPtr("smith"),
			UID:             uint32Ptr(121),
			PublicKey:       pub,
			PrimaryGroup:    primGrp,
			SecondaryGroups: noNameSecGrps,
		},
	}
	if e := DefaultDynamoDBStoreCreateUser(noNameSecGrpUser, ddbStore); e == nil {
		t.Error("Error not raised when unnamed secgrp user is passed")
	}

	noGIDSecGrp := &group.DefaultPosixGroup{
		Name: strPtr("secGrp3"),
	}
	noGIDSecGrps := []group.PosixGroup{
		noGIDSecGrp,
	}
	noGIDSecGrpUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:   strPtr("smith"),
			UID:             uint32Ptr(191),
			PublicKey:       pub,
			PrimaryGroup:    primGrp,
			SecondaryGroups: noGIDSecGrps,
		},
	}
	if e := DefaultDynamoDBStoreCreateUser(noGIDSecGrpUser, ddbStore); e == nil {
		t.Error("Error not raised when User and secgrp without GID is passed")
	}

	unknownSecGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(909),
		Name: strPtr("secGrp2"),
	}
	unknownSecGrps := []group.PosixGroup{
		unknownSecGrp,
	}
	unknownSecGrpUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:   strPtr("smith"),
			UID:             uint32Ptr(567),
			PublicKey:       pub,
			PrimaryGroup:    primGrp,
			SecondaryGroups: unknownSecGrps,
		},
	}
	if e := DefaultDynamoDBStoreCreateUser(unknownSecGrpUser, ddbStore); e == nil {
		t.Error("Error not raised when unknown secgrps user is passed")
	}
}

func TestDefaultDynamoDBStoreGetUser(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	grp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(345),
		Name: strPtr("secGrp1"),
	}
	secGrps := []group.PosixGroup{
		grp,
	}
	usr := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("smith"),
			UID:              uint32Ptr(123),
			PublicKey:        pub,
			PrimaryGroup:     primGrp,
			SecondaryGroups:  secGrps,
			LatestPasswdHash: strPtr("$1"),
			SudoClaims: []string{
				"smith locahost = /var/www/apache",
				"smith	locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	ddbSecGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("gpr"),
		DefaultPosixGroup:     grp,
	}
	if e := DefaultDynamoDBStoreCreateGroup(ddbSecGrp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	if e := DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}

	fetchUsrFilters := []*DefaultStoreUserFilter{
		&DefaultStoreUserFilter{
			PricipalNameProjection: strPtr("smith"),
			UserIDProjection:       strPtr("123"),
			EmailAddrProjection:    strPtr("email@email.com"),
		},
		&DefaultStoreUserFilter{
			UserIDProjection: strPtr("123"),
		},
		&DefaultStoreUserFilter{
			UserUniqueIdentifierProjection: strPtr("uuid"),
		},
		&DefaultStoreUserFilter{
			EmailAddrProjection: strPtr("email@email.com"),
		},
	}

	for _, filter := range fetchUsrFilters {
		result, e := DefaultDynamoDBStoreGetUser(filter, ddbStore)
		if e != nil {
			t.Errorf("Get User returned error %+v for filter %+v", e.Error(), filter)
		}
		if result == nil {
			t.Errorf("Get User did not return any result for filter %+v", filter)
		}
		defaultDynamoDBStoreUser, ok := result.(DefaultDynamoDBStoreUser)
		if !ok {
			t.Errorf("Get User returned a non DefaultDynamoDBStoreUser type")
		} else {
			if *defaultDynamoDBStoreUser.EmailAddress != *usr.EmailAddress ||
				*defaultDynamoDBStoreUser.PrincipalName != *usr.PrincipalName ||
				*defaultDynamoDBStoreUser.UID != *usr.UID ||
				*defaultDynamoDBStoreUser.LatestPasswdHash != *usr.LatestPasswdHash {
				t.Errorf("Get User returned user does not match up to created user for filter - %+v", filter)
			}
			if !bytes.Equal(defaultDynamoDBStoreUser.PublicKey.Marshal(), usr.PublicKey.Marshal()) {
				t.Errorf("Get User returned user's pub key %+v is not equal to what was put %+v", string(defaultDynamoDBStoreUser.PublicKey.Marshal()), string(usr.PublicKey.Marshal()))
			}
			if !reflect.DeepEqual(defaultDynamoDBStoreUser.PrimaryGroup, usr.PrimaryGroup) {
				t.Errorf("Get User returned user's primary group %+v is not equal to what was put %+v", defaultDynamoDBStoreUser.PrimaryGroup, usr.PrimaryGroup)
			}
			if !reflect.DeepEqual(defaultDynamoDBStoreUser.SecondaryGroups, usr.SecondaryGroups) {
				t.Errorf("Get User returned user's sec groups %+v are not equal to those that were put %+v", defaultDynamoDBStoreUser.SecondaryGroups, usr.SecondaryGroups)
			}
			if !reflect.DeepEqual(defaultDynamoDBStoreUser.SudoClaims, usr.SudoClaims) {
				t.Errorf("Get User returned user's sudo claims %+v are not equal to those that were put %+v", defaultDynamoDBStoreUser.SudoClaims, usr.SudoClaims)
			}
		}
		uuid := *defaultDynamoDBStoreUser.UserUniqueIdentifier
		fetchUsrFilters[2].UserUniqueIdentifierProjection = &uuid
	}

	nonDefaultStoreUserFilter := struct{ UserUniqueIdentifierProjection *string }{
		UserUniqueIdentifierProjection: strPtr("uuid"),
	}
	if _, e := DefaultDynamoDBStoreGetUser(nonDefaultStoreUserFilter, ddbStore); e == nil {
		t.Errorf("Get User returned did not err when nonDefaultStoreUserFilter is passed")
	}
}

func TestDefaultDynamoDBStoreUpdateUser(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client

	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	grp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(345),
		Name: strPtr("secGrp1"),
	}
	secGrps := []group.PosixGroup{
		grp,
	}
	usr := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("smith"),
			UID:              uint32Ptr(123),
			PublicKey:        pub,
			PrimaryGroup:     primGrp,
			SecondaryGroups:  secGrps,
			LatestPasswdHash: strPtr("$1"),
			SudoClaims: []string{
				"smith locahost = /var/www/apache",
				"smith	locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	ddbSecGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("gpr"),
		DefaultPosixGroup:     grp,
	}
	if e := DefaultDynamoDBStoreCreateGroup(ddbSecGrp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	if e := DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}
	filter := &DefaultStoreUserFilter{
		PricipalNameProjection: strPtr("smith"),
	}
	result, e := DefaultDynamoDBStoreGetUser(filter, ddbStore)
	if e != nil {
		t.Errorf("Get User returned error %+v for filter %+v", e.Error(), filter)
	}
	if result == nil {
		t.Errorf("Get User did not return any result for filter %+v", filter)
	}
	existingUsr, ok := result.(DefaultDynamoDBStoreUser)
	if !ok {
		t.Errorf("Get User returned a non DefaultDynamoDBStoreUser type")
	}

	newpub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1AFZhk0Om7OamGPyVA46dkTj42e4QV5dYrAES4pbxpCMZB1LmGC4L7V3CROsf8ek6ZK02XFIWgrIU0aVIr/EeDyj1bgemb12td8Ss1ZcrA8XGXzvd2A01sm3ucviiK3TLtaUgpbjJvSh1TPvjf50n1s4BdJ2oAQgJ4SWJHUEiW1fc09U9m/8uF33zwjccmtT3nUmQK0rI1kw4wbzRGzfZtZqI/dO3SeGUFgzvOVINA81VTTDo5ryq9UA13uhUC2Az5hel/KMJ3WJ9FTIXJS5+bPR1bXoAw4nWbu+URBWXYnsfw6h5rLERqH7FzYFs6wjSp4t+AtGhapriUMlQHmLEXgD2EL9kYmr/WLk+YOgz4+b3DKq3mAnk0ZUsU6HdZxX0V+/29Ov38ZKXouegncEBVoRfojE9T5ccCX3PiO25DkHah8fzNvXevK6YaeF3Yjd+zPQcdN8SkmDuUZM7WEeGoYr0mb9h45Iqio5jCLsRnAVedjNu0kedmSDjFd/R3zM="))
	newprimGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(543),
		Name: strPtr("modname"),
	}
	newgrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(232),
		Name: strPtr("secGrp2"),
	}
	newsecGrps := []group.PosixGroup{
		newgrp,
	}
	modusr := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: existingUsr.UserUniqueIdentifier,
		EmailAddress:         strPtr("change@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("htims"),
			UID:              uint32Ptr(213),
			PublicKey:        newpub,
			PrimaryGroup:     newprimGrp,
			SecondaryGroups:  newsecGrps,
			LatestPasswdHash: strPtr("$2"),
			SudoClaims: []string{
				"htims locahost = /var/www/apache",
				"htims locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	newddbSecGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("rpg"),
		DefaultPosixGroup:     newgrp,
	}
	if e := DefaultDynamoDBStoreCreateGroup(newddbSecGrp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	e = DefaultDynamoDBStoreUpdateUser(modusr, ddbStore)
	if e != nil {
		t.Errorf("Update user returned error - %+v", e.Error())
	} else {
		filter := &DefaultStoreUserFilter{
			UserUniqueIdentifierProjection: existingUsr.UserUniqueIdentifier,
		}
		result, e := DefaultDynamoDBStoreGetUser(filter, ddbStore)
		if e != nil {
			t.Errorf("Get User returned error %+v for filter %+v", e.Error(), filter)
		}
		if result == nil {
			t.Errorf("Get User did not return any result for filter %+v", filter)
		}
		modifiedUsr, ok := result.(DefaultDynamoDBStoreUser)
		if !ok {
			t.Errorf("Get User returned a non DefaultDynamoDBStoreUser type")
		}
		if *modusr.EmailAddress != *modifiedUsr.EmailAddress ||
			*modusr.PrincipalName != *modifiedUsr.PrincipalName ||
			*modusr.UID != *modifiedUsr.UID ||
			*modusr.LatestPasswdHash != *modifiedUsr.LatestPasswdHash {
			t.Error("Updated User does not match up to modifications sought")
		}
		if !bytes.Equal(modusr.PublicKey.Marshal(), modifiedUsr.PublicKey.Marshal()) {
			t.Errorf("Updated User's pub key %+v is not equal to what was sought %+v", string(modusr.PublicKey.Marshal()), string(modifiedUsr.PublicKey.Marshal()))
		}
		if !reflect.DeepEqual(modusr.PrimaryGroup, modifiedUsr.PrimaryGroup) {
			t.Errorf("Updated User's primary group %+v is not equal to what was sought %+v", modusr.PrimaryGroup, modifiedUsr.PrimaryGroup)
		}
		if !reflect.DeepEqual(modusr.SecondaryGroups, modifiedUsr.SecondaryGroups) {
			t.Errorf("Updated User's sec groups %+v are not equal to those that were sought %+v", modusr.SecondaryGroups, modifiedUsr.SecondaryGroups)
		}
		if !reflect.DeepEqual(modusr.SudoClaims, modifiedUsr.SudoClaims) {
			t.Errorf("Updated User's sudo claims %+v are not equal to those that were sought %+v", modusr.SudoClaims, modifiedUsr.SudoClaims)
		}
	}

	newpub2, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n"))
	newprimGrp2 := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(889),
		Name: strPtr("modname2"),
	}
	newgrp2 := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(2324),
		Name: strPtr("secGrp3"),
	}
	newsecGrps2 := []group.PosixGroup{
		newgrp2,
	}
	modusr2 := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: existingUsr.UserUniqueIdentifier,
		EmailAddress:         strPtr("change2@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("htims"),
			UID:              uint32Ptr(9999),
			PublicKey:        newpub2,
			PrimaryGroup:     newprimGrp2,
			SecondaryGroups:  newsecGrps2,
			LatestPasswdHash: strPtr("$3"),
			SudoClaims: []string{
				"htims2 locahost = /var/www/apache",
				"htims2 locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	newddbSecGrp2 := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("rpg2"),
		DefaultPosixGroup:     newgrp2,
	}
	if e := DefaultDynamoDBStoreCreateGroup(newddbSecGrp2, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	e = DefaultDynamoDBStoreUpdateUser(modusr2, ddbStore)
	if e != nil {
		t.Errorf("Update user returned error - %+v", e.Error())
	} else {
		filter := &DefaultStoreUserFilter{
			UserUniqueIdentifierProjection: existingUsr.UserUniqueIdentifier,
		}
		result, e := DefaultDynamoDBStoreGetUser(filter, ddbStore)
		if e != nil {
			t.Errorf("Get User returned error %+v for filter %+v", e.Error(), filter)
		}
		if result == nil {
			t.Errorf("Get User did not return any result %+v for filter %+v", e.Error(), filter)
		}
		modifiedUsr2, ok := result.(DefaultDynamoDBStoreUser)
		if !ok {
			t.Errorf("Get User returned a non DefaultDynamoDBStoreUser type")
		}
		if *modusr2.EmailAddress != *modifiedUsr2.EmailAddress ||
			*modusr2.PrincipalName != *modifiedUsr2.PrincipalName ||
			*modusr2.UID != *modifiedUsr2.UID ||
			*modusr2.LatestPasswdHash != *modifiedUsr2.LatestPasswdHash {
			t.Error("Updated User does not match up to modifications sought")
		}
		if !bytes.Equal(modusr2.PublicKey.Marshal(), modifiedUsr2.PublicKey.Marshal()) {
			t.Errorf("Updated User's pub key %+v is not equal to what was sought %+v", string(modusr2.PublicKey.Marshal()), string(modifiedUsr2.PublicKey.Marshal()))
		}
		if !reflect.DeepEqual(modusr2.PrimaryGroup, modifiedUsr2.PrimaryGroup) {
			t.Errorf("Updated User's primary group %+v is not equal to what was sought %+v", modusr2.PrimaryGroup, modifiedUsr2.PrimaryGroup)
		}
		if !reflect.DeepEqual(modusr2.SecondaryGroups, modifiedUsr2.SecondaryGroups) {
			t.Errorf("Updated User's sec groups %+v are not equal to those that were sought %+v", modusr2.SecondaryGroups, modifiedUsr2.SecondaryGroups)
		}
		if !reflect.DeepEqual(modusr2.SudoClaims, modifiedUsr2.SudoClaims) {
			t.Errorf("Updated User's sudo claims %+v are not equal to those that were sought %+v", modusr2.SudoClaims, modifiedUsr2.SudoClaims)
		}
	}
}

func TestDefaultDynamoDBStoreDeleteUser(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client

	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	grp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(345),
		Name: strPtr("secGrp1"),
	}
	secGrps := []group.PosixGroup{
		grp,
	}
	usr := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("uuid"),
		EmailAddress:         strPtr("email@email.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("smith"),
			UID:              uint32Ptr(123),
			PublicKey:        pub,
			PrimaryGroup:     primGrp,
			SecondaryGroups:  secGrps,
			LatestPasswdHash: strPtr("$1"),
			SudoClaims: []string{
				"smith locahost = /var/www/apache",
				"smith	locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	ddbSecGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("gpr"),
		DefaultPosixGroup:     grp,
	}
	if e := DefaultDynamoDBStoreCreateGroup(ddbSecGrp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}
	if e := DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}
	filter := &DefaultStoreUserFilter{
		PricipalNameProjection: strPtr("smith"),
	}
	result, e := DefaultDynamoDBStoreGetUser(filter, ddbStore)
	if e != nil {
		t.Errorf("Get User returned error %+v for filter %+v", e.Error(), filter)
	}
	if result == nil {
		t.Errorf("Get User did not return any result %+v for filter %+v", e.Error(), filter)
	}

	deleteUsr := &user.DefaultPosixUser{
		PrincipalName: strPtr("smith"),
	}
	e = DefaultDynamoDBStoreDeleteUser(deleteUsr, ddbStore)
	if e != nil {
		t.Errorf("Delete User returned error - %+v", e.Error())
	}
	result, e = DefaultDynamoDBStoreGetUser(filter, ddbStore)
	if e != nil {
		t.Errorf("Get User returned error %+v for filter %+v", e.Error(), filter)
	}
	if result != nil {
		t.Error("Get User did not return nil result after user deletion")
	}
	items, er := appendUserSecondaryGroupsByUser(ddbStore.DDBClient, *ddbStore.TableName, "smith", []Item{})
	if er != nil {
		t.Errorf("append user secondary groups errored out - %+v", er)
	}
	if len(items) != 0 {
		t.Errorf("Length of user secondary groups for deleted user is not zero")
	}

	nonExistant := &user.DefaultPosixUser{
		PrincipalName: strPtr("non-existant"),
	}
	e = DefaultDynamoDBStoreDeleteUser(nonExistant, ddbStore)
	if e == nil {
		t.Errorf("Delete User returned no error for non-existant error - %+v", e.Error())
	}
}

func TestFetchUserByPK(t *testing.T) {

}

func TestFetchUserByGsi(t *testing.T) {

}

func TestAppendUserSecondaryGroupsByUser(t *testing.T) {

}

func TestPutUser(t *testing.T) {

}

func TestUidVacancyCheck(t *testing.T) {

}

func TestUpdateUserByPrimaryKey(t *testing.T) {}

func TestUpdateUserByUUID(t *testing.T) {}

func TestAppendUserPutTransactions(t *testing.T) {}

func TestAppendUserDeleteTransactions(t *testing.T) {}

func TestDefaultDynamoDBStoreUserUnmarshalJSON(t *testing.T) {
	rawUsr := json.RawMessage(`{
		"uuid": "e40981a1-110b-4835-dksk-kdsclccd",
		"email": "perm@perm.com",
		"principalName": "perm",
		"uid": 9929,
		"publicKey": "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n",
		"primaryGroup": {
			"gid": 9930,
			"name": "perms"
		},
		"secondaryGroups": [
		{
			"gid": 2322,
			"name": "webdev"
		},
		{
			"gid": 9959,
			"name": "admin"
		}
		],
		"latestPasswdHash": "$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1",
		"sudoClaims": ["htims locahost = /var/www/apache","htims locahost = (root)   NOPASSWD: tail  /var/log/messages"]
		}`)
	bytes, err := json.Marshal(&rawUsr)
	if err != nil {
		panic(err)
	}
	usr := &DefaultDynamoDBStoreUser{
		DefaultPosixUser: &user.DefaultPosixUser{},
	}
	e := usr.UnmarshalJSON(bytes)
	if e != nil {
		t.Errorf("Failed to unmarshal user json %+v", e.Error())
	}

	validateUsr := &DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("e40981a1-110b-4835-dksk-kdsclccd"),
		EmailAddress:         strPtr("perm@perm.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("perm"),
			UID:              uint32Ptr(9929),
			LatestPasswdHash: strPtr("$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1"),
			SudoClaims: []string{
				"htims locahost = /var/www/apache",
				"htims locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	pubKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n"))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(9930),
		Name: strPtr("perms"),
	}
	secGrps := []group.PosixGroup{
		&group.DefaultPosixGroup{
			Gid:  uint16Ptr(2322),
			Name: strPtr("webdev"),
		},
		&group.DefaultPosixGroup{
			Gid:  uint16Ptr(9959),
			Name: strPtr("admin"),
		},
	}
	validateUsr.PublicKey = pubKey
	validateUsr.PrimaryGroup = primGrp
	validateUsr.SecondaryGroups = secGrps

	if !reflect.DeepEqual(validateUsr, usr) {
		t.Error("Marshaled user is not matching up to sent user")
	}
}

func TestDefaultDynamoDBStoreUserMarshalJSON(t *testing.T) {
	usr := &DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: strPtr("e40981a1-110b-4835-dksk-kdsclccd"),
		EmailAddress:         strPtr("perm@perm.com"),
		DefaultPosixUser: &user.DefaultPosixUser{
			PrincipalName:    strPtr("perm"),
			UID:              uint32Ptr(9929),
			LatestPasswdHash: strPtr("$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1"),
			SudoClaims: []string{
				"htims locahost = /var/www/apache",
				"htims locahost = (root)   NOPASSWD: tail  /var/log/messages",
			},
		},
	}
	pubKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n"))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(9930),
		Name: strPtr("perms"),
	}
	secGrps := []group.PosixGroup{
		&group.DefaultPosixGroup{
			Gid:  uint16Ptr(2322),
			Name: strPtr("webdev"),
		},
		&group.DefaultPosixGroup{
			Gid:  uint16Ptr(9959),
			Name: strPtr("admin"),
		},
	}
	usr.PublicKey = pubKey
	usr.PrimaryGroup = primGrp
	usr.SecondaryGroups = secGrps
	usrBytes, e := usr.MarshalJSON()
	if e != nil {
		t.Errorf("Marshaljson returned error %+v", e.Error())
	}

	rawUsr := json.RawMessage(`{
		"uuid": "e40981a1-110b-4835-dksk-kdsclccd",
		"email": "perm@perm.com",
		"principalName": "perm",
		"uid": 9929,
		"publicKey": "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n",
		"primaryGroup": {
			"gid": 9930,
			"name": "perms"
		},
		"secondaryGroups": [
		{
			"gid": 2322,
			"name": "webdev"
		},
		{
			"gid": 9959,
			"name": "admin"
		}
		],
		"latestPasswdHash": "$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1",
		"sudoClaims": ["htims locahost = /var/www/apache","htims locahost = (root)   NOPASSWD: tail  /var/log/messages"]
		}`)
	rawBytes, err := json.Marshal(&rawUsr)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(usrBytes, rawBytes) {
		t.Errorf("Marshaljson of user is not the same as raw json")
	}
}
