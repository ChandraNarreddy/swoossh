package storage

import (
	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/user"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"golang.org/x/crypto/ssh"
)

var (
	//Constants for DDB table
	DDBRecordPK                         = "pk"
	DDBRecordSK                         = "sk"
	DDBRecordNameKey                    = "name"
	DDBRecordEmailKey                   = "email"
	DDBRecordUUIDKey                    = "uuid"
	DDBRecordCreatedKey                 = "created"
	DDBRecordTypeKey                    = "type"
	DDBRecordPosixIdKey                 = "posix_id"
	DDBRecordUserPrimaryGroupKey        = "user_primary_group"
	DDBRecordPublicKeyKey               = "public_key"
	DDBRecordValidKey                   = "valid"
	DDBRecordSecondaryGroupKey          = "secondary_group"
	DDBRecordUserPrimaryGroupPosixIdKey = "user_primary_group_posix_id"
	DDBRecordUserPasswordHashKey        = "passwd_hash"
	DDBRecordUserSudoClaimsKey          = "sudo_claims"
	DDBRecordCertificateKey             = "certificate"

	DDBUserRecordPKPrefix               = "user#"
	DDBUserRecordSKPrefix               = "user#"
	DDBUserCertificateRecordPKPrefix    = "user#"
	DDBUserCertificateRecordSKPrefix    = "cert#expiry#"
	DDBUserSecondaryGroupRecordPKPrefix = "user#"
	DDBUserSecondaryGroupRecordSKPrefix = "sg#"
	DDBGroupRecordPKPrefix              = "group#posix#"
	DDBGroupRecordSKPrefix              = "group#posix#"

	// GSI Indexes constants
	DDBGsiUUIDPK           = DDBRecordUUIDKey
	DDBGsiPosixIDPK        = DDBRecordPosixIdKey
	DDBGsiPosixIDSK        = DDBRecordTypeKey
	DDBGsiSecondaryGroupPK = DDBRecordSecondaryGroupKey
	DDBGsiSecondaryGroupSK = DDBRecordPK
	DDBGsiNamePK           = DDBRecordNameKey
	DDBGsiNameSK           = DDBRecordTypeKey
	DDBGsiEmailPK          = DDBRecordEmailKey
	DDBGsiTypePK           = DDBRecordTypeKey
	DDBGsiTypeSK           = DDBRecordPK

	DDBRecordTypeUserEnum     = "user"
	DDBRecordTypeGroupEnum    = "group"
	DDBRecordTypeUserCertEnum = "user_cert"

	DDBUserRecordValidFalseEnum = "False"

	DDBISO8601DateTimeFormat = "2006-01-02T15:04:05.000Z"
)

type DDBQueryOrder int

const (
	DDBQueryOrderForward DDBQueryOrder = iota + 1
	DDBQueryOrderReverse
)

func (w DDBQueryOrder) String() string {
	return [...]string{"Forward", "Reverse"}[w-1]
}
func (d DDBQueryOrder) EnumIndex() int {
	return int(d)
}

type Item struct {
	PK                      string   `dynamodbav:"pk"`
	SK                      string   `dynamodbav:"sk"`
	Name                    string   `dynamodbav:"name,omitempty"`
	Email                   string   `dynamodbav:"email,omitempty"`
	UUID                    string   `dynamodbav:"uuid,omitempty"`
	Created                 string   `dynamodbav:"created,omitempty"`
	Type                    string   `dynamodbav:"type,omitempty"`
	PosixId                 string   `dynamodbav:"posix_id,omitempty"`
	UserPrimaryGroup        string   `dynamodbav:"user_primary_group,omitempty"`
	PublicKey               string   `dynamodbav:"public_key,omitempty"`
	Valid                   string   `dynamodbav:"valid,omitempty"`
	SecondaryGroup          string   `dynamodbav:"secondary_group,omitempty"`
	UserPrimaryGroupPosixId string   `dynamodbav:"user_primary_group_posix_id,omitempty"`
	PasswordHash            string   `dynamodbav:"passwd_hash,omitempty"`
	SudoClaims              []string `dynamodbav:"sudo_claims,omitempty"`
	Certificate             string   `dynamodbav:"certificate,omitempty"`
}

type DefaultDynamoDBStore struct {
	DDBClient                  dynamodbiface.DynamoDBAPI
	TableName                  *string
	GSIPosixIDIndexName        *string
	GSIUUIDIndexName           *string
	GSISecondaryGroupIndexName *string
	GSINameIndexName           *string
	GSIEmailIndexName          *string
	GSITypeIndexName           *string
}

func (c *DefaultDynamoDBStore) SearchUsers(filter UserFilter) (UserSearchResp, error) {
	return DefaultDynamoDBStoreSearchUsers(filter, c)
}

func (c *DefaultDynamoDBStore) CreateUser(user user.User) error {
	return DefaultDynamoDBStoreCreateUser(user, c)
}

func (c *DefaultDynamoDBStore) GetUser(filter UserFilter) (user.User, error) {
	return DefaultDynamoDBStoreGetUser(filter, c)
}

func (c *DefaultDynamoDBStore) UpdateUser(user user.User) error {
	return DefaultDynamoDBStoreUpdateUser(user, c)
}

func (c *DefaultDynamoDBStore) DeleteUser(user user.User) error {
	return DefaultDynamoDBStoreDeleteUser(user, c)
}

func (c *DefaultDynamoDBStore) SearchGroups(filter GroupFilter) (GroupSearchResp, error) {
	return DefaultDynamoDBStoreSearchGroups(filter, c)
}

func (c *DefaultDynamoDBStore) CreateGroup(group group.Group) error {
	return DefaultDynamoDBStoreCreateGroup(group, c)
}

func (c *DefaultDynamoDBStore) GetGroup(filter GroupFilter) (group.Group, error) {
	return DefaultDynamoDBStoreGetGroup(filter, c)
}

func (c *DefaultDynamoDBStore) UpdateGroup(group group.Group) error {
	return DefaultDynamoDBStoreUpdateGroup(group, c)
}

func (c *DefaultDynamoDBStore) DeleteGroup(group group.Group) error {
	return DefaultDynamoDBStoreDeleteGroup(group, c)
}

func (c *DefaultDynamoDBStore) PutSSHCertForUser(cert *ssh.Certificate, usr user.User) error {
	return DefaultDynamoDBStorePutSSHCertForUser(cert, usr, c)
}

func (c *DefaultDynamoDBStore) GetSSHCertsForUser(filter SSHCertSearchFilter) (SSHCertSearchResp, error) {
	return DefaultDynamoDBStoreGetSSHCertsForUser(filter, c)
}
