package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/user"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type DefaultStoreUserFilter struct {
	PricipalNameProjection         *string
	UserIDProjection               *string
	UserUniqueIdentifierProjection *string
	EmailAddrProjection            *string
}

type DefaultStoreUserSearchFilter struct {
	UserNameSearchProjection *string
	PageToken                *string
	PageSize                 *int
	Order                    *DDBQueryOrder
}

type DefaultDynamoDBStoreUser struct {
	UserUniqueIdentifier *string `json:"uuid,omitempty"`
	EmailAddress         *string `json:"email,omitempty"`
	*user.DefaultPosixUser
}

func (c *DefaultDynamoDBStoreUser) GetUser() user.User {
	return c
}

type DefaultStoreUserSearchResponse struct {
	Result            []*DefaultDynamoDBStoreUser
	NextPageToken     *string
	PreviousPageToken *string
}

func (c *DefaultStoreUserSearchResponse) GetUserSearchResults() []UserSearchResult {
	if len(c.Result) == 0 {
		return nil
	}
	result := make([]UserSearchResult, 0)
	for _, each := range c.Result {
		result = append(result, each)
	}
	return result
}

func DefaultDynamoDBStoreSearchUsers(filter UserFilter, store *DefaultDynamoDBStore) (UserSearchResp, error) {
	userFilter, ok := filter.(*DefaultStoreUserSearchFilter)
	if !ok {
		log.Print("User Filter passed could not be cast to DefaultStoreUserSearchFilter")
		return nil, fmt.Errorf("User Filter passed could not be cast to DefaultStoreUserSearchFilter")
	}
	var nameSearchFilter string
	if userFilter.UserNameSearchProjection != nil {
		nameSearchFilter = *userFilter.UserNameSearchProjection
	} else {
		log.Print("User filter passed does not contain a search projection, can't continue")
		return nil, fmt.Errorf("User filter passed does not contain a search projection")
	}
	userNameKeyConditionBuilder := expression.KeyAnd(
		expression.Key(DDBGsiTypePK).Equal(expression.Value(DDBRecordTypeUserEnum)),
		expression.Key(DDBGsiTypeSK).BeginsWith(DDBUserRecordPKPrefix+nameSearchFilter),
	)
	proj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordNameKey),
		expression.Name(DDBRecordEmailKey),
		expression.Name(DDBRecordUUIDKey),
		expression.Name(DDBRecordCreatedKey),
		expression.Name(DDBRecordTypeKey),
		expression.Name(DDBRecordPosixIdKey),
		expression.Name(DDBRecordUserPrimaryGroupKey),
		expression.Name(DDBRecordPublicKeyKey),
		expression.Name(DDBRecordValidKey),
		expression.Name(DDBRecordUserPrimaryGroupPosixIdKey),
		expression.Name(DDBRecordUserSudoClaimsKey),
		expression.Name(DDBRecordUserPasswordHashKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(userNameKeyConditionBuilder).
		WithProjection(proj).
		Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching users for key condition %+v", userNameKeyConditionBuilder)
		return nil, fmt.Errorf("Failed to build DDB expression while fetching users for key condition %+v", userNameKeyConditionBuilder)
	}
	usersQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(*store.TableName),
		IndexName:                 aws.String(*store.GSITypeIndexName),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}
	if userFilter.Order != nil {
		if *userFilter.Order == DDBQueryOrderReverse {
			fal := false
			usersQueryInput.ScanIndexForward = &fal
		}
	}
	var size *int64
	if userFilter.PageSize != nil {
		tmp := int64(*userFilter.PageSize)
		size = &tmp
	}

	var exclusiveStartKey, lastEvaluatedKey map[string]*dynamodb.AttributeValue
	if userFilter.PageToken != nil {
		var decodeTokenErr error
		exclusiveStartKey, decodeTokenErr = decodePageToken(*userFilter.PageToken)
		if decodeTokenErr != nil {
			log.Printf("Failure in decoding page token for key condition %+v", userNameKeyConditionBuilder)
			return nil, fmt.Errorf("Failure in decoding page token for key condition %+v", userNameKeyConditionBuilder)
		}
	}

	userResults := make([]*DefaultDynamoDBStoreUser, 0)
	var lastEvaluatedKeyEncodedToken string
	var firstEvaluatedKeyEncodedToken string
	for i := 0; ; {
		if size != nil {
			usersQueryInput.Limit = size
		}
		if exclusiveStartKey != nil {
			usersQueryInput.ExclusiveStartKey = exclusiveStartKey
		}
		usersQueryResult, usersQueryErr := store.DDBClient.Query(usersQueryInput)
		if usersQueryErr != nil {
			log.Printf("Error querying users for key condition %+v - %+v", userNameKeyConditionBuilder, usersQueryErr)
			return nil, fmt.Errorf("Error querying users for key condition %+v", userNameKeyConditionBuilder)
		}
		if len(usersQueryResult.Items) > 0 {
			userItems := []Item{}
			if err := dynamodbattribute.UnmarshalListOfMaps(usersQueryResult.Items, &userItems); err != nil {
				log.Printf("Failed to unmarshall user results for key condition %+v", userNameKeyConditionBuilder)
				continue
			}
			for _, item := range userItems {
				usr := strings.TrimPrefix(item.PK, DDBUserRecordPKPrefix)
				var pubKey ssh.PublicKey
				if item.PublicKey != "" {
					var parseErr error
					pubKey, _, _, _, parseErr = ssh.ParseAuthorizedKey([]byte(item.PublicKey))
					if parseErr != nil {
						log.Printf("Failed to parse ssh key of user %s from authorizedkeys format", usr)
					}
				}
				uuid := item.UUID
				email := item.Email

				var userPosixID32 *uint32
				if item.PosixId != "" {
					userPosixID, parseErr := strconv.ParseUint(item.PosixId, 10, 32)
					if parseErr != nil {
						log.Printf("Failed to parse posix id %s of user %s", item.PosixId, usr)
					} else {
						tmp := uint32(userPosixID)
						userPosixID32 = &tmp
					}
				}

				var userPrimaryGroupPosixID16 *uint16
				if item.UserPrimaryGroupPosixId != "" {
					grpPosixID, parseErr := strconv.ParseUint(item.UserPrimaryGroupPosixId, 10, 16)
					if parseErr != nil {
						log.Printf("Failed to parse posix id %s of user's primary group %s", item.UserPrimaryGroupPosixId, item.UserPrimaryGroup)
					}
					tmp := uint16(grpPosixID)
					userPrimaryGroupPosixID16 = &tmp
				}

				var userPrimaryGroupName string
				if item.UserPrimaryGroup != "" {
					userPrimaryGroupName = item.UserPrimaryGroup
				}

				userPrimaryGroup := &group.DefaultPosixGroup{
					Gid:  userPrimaryGroupPosixID16,
					Name: &userPrimaryGroupName,
				}
				passwdHash := item.PasswordHash
				posixUser := &user.DefaultPosixUser{
					PrincipalName:    &usr,
					UID:              userPosixID32,
					PublicKey:        pubKey,
					PrimaryGroup:     userPrimaryGroup,
					LatestPasswdHash: &passwdHash,
					SudoClaims:       item.SudoClaims,
				}
				defaultDynamoDBUser := DefaultDynamoDBStoreUser{
					UserUniqueIdentifier: &uuid,
					DefaultPosixUser:     posixUser,
					EmailAddress:         &email,
				}
				if userFilter.Order != nil {
					if *userFilter.Order == DDBQueryOrderReverse {
						userResults = append([]*DefaultDynamoDBStoreUser{&defaultDynamoDBUser}, userResults...)
					} else {
						userResults = append(userResults, &defaultDynamoDBUser)
					}
				} else {
					userResults = append(userResults, &defaultDynamoDBUser)
				}
			}
			if i == 0 {
				firstEvaluatedResult := Item{
					PK:   userItems[0].PK,
					SK:   userItems[0].SK,
					Type: userItems[0].Type,
				}
				firstEvaluatedResultItem, marshalErr := dynamodbattribute.MarshalMap(firstEvaluatedResult)
				if marshalErr != nil {
					log.Printf("Failed to marshal firstEvaluatedResult - %+v", marshalErr)
					return nil, fmt.Errorf("Failed to marshal firstEvaluatedResult - %+v", marshalErr)
				}
				var encodeErr error
				firstEvaluatedKeyEncodedToken, encodeErr = encodeLastEvaluatedKey(firstEvaluatedResultItem)
				if encodeErr != nil {
					log.Printf("Failed to encode first result item for key condition %+v - %+v", userNameKeyConditionBuilder, encodeErr)
					return nil, fmt.Errorf("Failed to encode first result item for key condition %+v", userNameKeyConditionBuilder)
				}
			}
		}
		if len(usersQueryResult.LastEvaluatedKey) != 0 {
			if int64(len(usersQueryResult.Items)) == *size {
				lastEvaluatedKey = usersQueryResult.LastEvaluatedKey
				var encodeErr error
				lastEvaluatedKeyEncodedToken, encodeErr = encodeLastEvaluatedKey(lastEvaluatedKey)
				if encodeErr != nil {
					log.Printf("Failed to encode lastEvaluatedKey for key condition %+v - %+v", userNameKeyConditionBuilder, encodeErr)
					return nil, fmt.Errorf("Failed to encode lastEvaluatedKey for key condition %+v", userNameKeyConditionBuilder)
				}
				break
			} else {
				tmp := *size - int64(len(usersQueryResult.Items))
				size = &tmp
				exclusiveStartKey = usersQueryResult.LastEvaluatedKey
			}
		} else {
			break
		}
	}
	if len(userResults) == 0 {
		log.Printf("No users found for key condition %+v", userNameKeyConditionBuilder)
		resp := &DefaultStoreUserSearchResponse{
			Result:            nil,
			NextPageToken:     nil,
			PreviousPageToken: nil,
		}
		return resp, nil
	}

	resp := &DefaultStoreUserSearchResponse{
		Result:            userResults,
		NextPageToken:     &lastEvaluatedKeyEncodedToken,
		PreviousPageToken: &firstEvaluatedKeyEncodedToken,
	}

	if userFilter.Order != nil && *userFilter.Order == DDBQueryOrderReverse {
		resp.NextPageToken = &firstEvaluatedKeyEncodedToken
		resp.PreviousPageToken = &lastEvaluatedKeyEncodedToken
	}
	return resp, nil
}

func DefaultDynamoDBStoreCreateUser(usr user.User, store *DefaultDynamoDBStore) error {
	ddbUser, ok := usr.(DefaultDynamoDBStoreUser)
	if !ok {
		log.Printf("The user passed %s does not implement Posix User interface. Cannot add user", *usr.GetPrincipalName())
		return fmt.Errorf("The user passed %s does not implement Posix User interface. Cannot add user", *usr.GetPrincipalName())
	}
	if ddbUser.GetPrincipalName() == nil {
		log.Printf("Principal Name is empty, cannot create user")
		return fmt.Errorf("Principal Name cannot be empty")
	}
	principalName := *ddbUser.GetPrincipalName()
	if ddbUser.GetUID() == nil {
		log.Printf("UID is empty, cannot create user")
		return fmt.Errorf("UID cannot be empty")
	}
	uid := *ddbUser.GetUID()
	if ddbUser.EmailAddress == nil {
		log.Printf("EmailAddress is empty, cannot create user")
		return fmt.Errorf("EmailAddress cannot be empty")
	}
	emailAddr := *ddbUser.EmailAddress
	secGroups := ddbUser.GetUserSecondaryGroups()
	uuid, uuidErr := uuid.NewRandom()
	if uuidErr != nil {
		log.Printf("Failed to generate uuid while creating user %s", principalName)
		return fmt.Errorf("Failed to generate uuid while creating user %s", principalName)
	}
	uuidStr := uuid.String()

	var publicKey string
	if ddbUser.GetPublicKey() != nil {
		publicKeyBytes := ssh.MarshalAuthorizedKey(ddbUser.GetPublicKey())
		publicKey = string(publicKeyBytes)
	}
	userItem := Item{
		PK:        DDBUserRecordPKPrefix + principalName,
		SK:        DDBUserRecordSKPrefix + principalName,
		Name:      principalName,
		UUID:      uuidStr,
		Email:     emailAddr,
		Created:   time.Now().UTC().Format(DDBISO8601DateTimeFormat),
		Type:      DDBRecordTypeUserEnum,
		PosixId:   strconv.FormatUint(uint64(uid), 10),
		PublicKey: string(publicKey),
	}

	if ddbUser.GetPrimaryGroup().GetGroupName() != nil {
		userItem.UserPrimaryGroup = *ddbUser.GetPrimaryGroup().GetGroupName()
	}
	if ddbUser.GetPrimaryGroup().GetGroupID() != nil {
		userItem.UserPrimaryGroupPosixId = strconv.FormatUint(uint64(*ddbUser.GetPrimaryGroup().GetGroupID()), 10)
	}
	if latestPasswdHash, ok := usr.(user.UserLatestPasswdHash); ok && latestPasswdHash.GetLatestPasswdHash() != nil {
		userItem.PasswordHash = *latestPasswdHash.GetLatestPasswdHash()
	}
	if sudoClaims, ok := usr.(user.UserSudoClaims); ok && sudoClaims.GetUserSudoClaims() != nil {
		userItem.SudoClaims = sudoClaims.GetUserSudoClaims()
	}
	userSecGroupItems := make([]Item, 0)
	for _, group := range secGroups {
		if group.GetGroupName() == nil {
			log.Printf("Secondary Group's Name is empty, cannot create user")
			return fmt.Errorf("Secondary Group's Name cannot be empty")
		}
		secGrpName := *group.GetGroupName()
		if group.GetGroupID() == nil {
			log.Printf("Secondary Group's ID is empty, cannot create user")
			return fmt.Errorf("Secondary Group's ID cannot be empty")
		}
		secGrpID := *group.GetGroupID()
		userSecGroupItem := Item{
			PK:             DDBUserSecondaryGroupRecordPKPrefix + principalName,
			SK:             DDBUserSecondaryGroupRecordSKPrefix + secGrpName,
			PosixId:        strconv.FormatUint(uint64(secGrpID), 10),
			SecondaryGroup: secGrpName,
		}
		userSecGroupItems = append(userSecGroupItems, userSecGroupItem)
	}

	//check for UID vacancy here
	uidVacant, vacancyCheckErr := uidVacancyCheck(store.DDBClient, *store.TableName,
		*store.GSIPosixIDIndexName, userItem, false)
	if vacancyCheckErr != nil {
		log.Printf("UID vacancy checking failed while creating user %s", principalName)
		return fmt.Errorf("GID vacancy checking failed while creating user %s", principalName)
	}
	if !uidVacant {
		log.Printf("UID %d is not vacant to create user %s", uid, principalName)
		return fmt.Errorf("GID %d is not vacant to create group %s", uid, principalName)
	}

	putUserErr := putUser(store.DDBClient, *store.TableName, userItem, userSecGroupItems, false)
	if putUserErr != nil {
		log.Printf("Failed to create user %s - %+v", principalName, putUserErr)
		return fmt.Errorf("Failed to create user %s", principalName)
	}
	return nil
}

func DefaultDynamoDBStoreGetUser(filter UserFilter, store *DefaultDynamoDBStore) (user.User, error) {
	userFilter, ok := filter.(*DefaultStoreUserFilter)
	if !ok {
		log.Print("User Filter passed could not be cast to DefaultStoreUserFilter")
		return nil, fmt.Errorf("User Filter passed could not be cast to DefaultStoreUserFilter")
	}
	userItem := Item{}
	if userFilter.PricipalNameProjection != nil {
		userPrimaryKey := map[string]string{
			DDBRecordPK: DDBUserRecordPKPrefix + *userFilter.PricipalNameProjection,
			DDBRecordSK: DDBUserRecordSKPrefix + *userFilter.PricipalNameProjection,
		}
		fetchUserErr := fetchUserByPK(store.DDBClient, *store.TableName, userPrimaryKey, &userItem)
		if fetchUserErr != nil {
			log.Printf("Failure in fetching user for filter %+v - %+v", *userFilter.PricipalNameProjection, fetchUserErr)
			return nil, fmt.Errorf("Failure in fetching user for filter %+v", *userFilter.PricipalNameProjection)
		}
	}
	if userFilter.UserUniqueIdentifierProjection != nil && userItem.PK == "" {
		uuidKeyConditionBuilder := expression.KeyEqual(expression.Key(DDBGsiUUIDPK), expression.Value(*(userFilter.UserUniqueIdentifierProjection)))
		fetchUserErr := fetchUserByGsi(store.DDBClient, *store.TableName, *store.GSIUUIDIndexName, uuidKeyConditionBuilder, &userItem)
		if fetchUserErr != nil {
			log.Printf("Failure in fetching user for filter %+v - %+v", *(userFilter.UserUniqueIdentifierProjection), fetchUserErr)
			return nil, fmt.Errorf("Failure in fetching user for filter %+v", *(userFilter.UserUniqueIdentifierProjection))
		}
	}
	if userFilter.UserIDProjection != nil && userItem.PK == "" {
		posixIdKeyConditionBuilder := expression.KeyAnd(
			expression.KeyEqual(expression.Key(DDBGsiPosixIDPK), expression.Value(*(userFilter.UserIDProjection))),
			expression.KeyEqual(expression.Key(DDBGsiPosixIDSK), expression.Value(DDBRecordTypeUserEnum)))
		fetchUserErr := fetchUserByGsi(store.DDBClient, *store.TableName, *store.GSIPosixIDIndexName, posixIdKeyConditionBuilder, &userItem)
		if fetchUserErr != nil {
			log.Printf("Failure in fetching user for filter %+v - %+v", *(userFilter.UserIDProjection), fetchUserErr)
			return nil, fmt.Errorf("Failure in fetching user for filter %+v", *(userFilter.UserIDProjection))
		}
	}
	if userFilter.EmailAddrProjection != nil && userItem.PK == "" {
		emailAddrKeyConditionBuilder := expression.KeyEqual(expression.Key(DDBGsiEmailPK), expression.Value(*(userFilter.EmailAddrProjection)))
		fetchUserErr := fetchUserByGsi(store.DDBClient, *store.TableName, *store.GSIEmailIndexName, emailAddrKeyConditionBuilder, &userItem)
		if fetchUserErr != nil {
			log.Printf("Failure in fetching user for filter %+v - %+v", *(userFilter.EmailAddrProjection), fetchUserErr)
			return nil, fmt.Errorf("Failure in fetching user for filter %+v", *(userFilter.EmailAddrProjection))
		}
	}
	if userItem.PK == "" {
		log.Print("Found no user record for the filters passed")
		return nil, nil
	}
	usr := strings.TrimPrefix(userItem.PK, DDBUserRecordPKPrefix)
	email := userItem.Email
	// Querying for all secondary groups of the user
	userSecGroupItems := []Item{}
	userSecGroupItems, appendUserSecondaryGroupsErr := appendUserSecondaryGroupsByUser(store.DDBClient, *store.TableName, usr, userSecGroupItems)
	if appendUserSecondaryGroupsErr != nil {
		log.Printf("Failed to fetch secondary groups of user %s - %+v", usr, appendUserSecondaryGroupsErr)
		return nil, fmt.Errorf("Failed to fetch secondary groups of user %s", usr)
	}

	var userSecGroups []group.PosixGroup
	if len(userSecGroupItems) > 0 {
		for _, eachItem := range userSecGroupItems {
			grpName := eachItem.SecondaryGroup
			userSecGroup := &group.DefaultPosixGroup{
				Name: &grpName,
			}
			if eachItem.PosixId != "" {
				gid, gidParseError := strconv.ParseUint(eachItem.PosixId, 10, 16)
				if gidParseError != nil {
					log.Printf("Failed to parse group id %s of secondary group %s for user %s", eachItem.PosixId, eachItem.SecondaryGroup, usr)
					return nil, fmt.Errorf("Failed to parse group id %s of secondary group %s for user %s", eachItem.PosixId, eachItem.SecondaryGroup, usr)
				}
				gid16 := uint16(gid)
				userSecGroup.Gid = &(gid16)
			}
			userSecGroups = append(userSecGroups, userSecGroup)
		}
	}
	var pubKey ssh.PublicKey
	if userItem.PublicKey != "" {
		var parseErr error
		pubKey, _, _, _, parseErr = ssh.ParseAuthorizedKey([]byte(userItem.PublicKey))
		if parseErr != nil {
			log.Printf("Failed to parse ssh key of user %s from authorizedkeys format", usr)
			//return nil, fmt.Errorf("Failed to parse ssh key of user %s from authorizedkeys format", usr)
		}
	}

	userPosixId, parseErr := strconv.ParseUint(userItem.PosixId, 10, 32)
	if parseErr != nil {
		log.Printf("Failed to parse posix id %s of user %s", userItem.PosixId, usr)
		return nil, fmt.Errorf("Failed to parse posix id %s of user %s", userItem.PosixId, usr)
	}
	userPosixId32 := uint32(userPosixId)

	userPrimaryGroupPosixId, parseErr := strconv.ParseUint(userItem.UserPrimaryGroupPosixId, 10, 16)
	if parseErr != nil {
		log.Printf("Failed to parse posix id %s of user's primary group %s", userItem.UserPrimaryGroupPosixId, userItem.UserPrimaryGroup)
		return nil, fmt.Errorf("Failed to parse posix id %s of user's primary group %s", userItem.UserPrimaryGroupPosixId, userItem.UserPrimaryGroup)
	}
	userPrimaryGroupPosixId16 := uint16(userPrimaryGroupPosixId)
	userPrimaryGroupName := userItem.UserPrimaryGroup
	userPrimaryGroup := &group.DefaultPosixGroup{
		Gid:  &(userPrimaryGroupPosixId16),
		Name: &userPrimaryGroupName,
	}
	passwdHash := userItem.PasswordHash
	posixUser := &user.DefaultPosixUser{
		PrincipalName:    &usr,
		UID:              &userPosixId32,
		PublicKey:        pubKey,
		PrimaryGroup:     userPrimaryGroup,
		SecondaryGroups:  userSecGroups,
		LatestPasswdHash: &passwdHash,
		SudoClaims:       userItem.SudoClaims,
	}
	uuid := userItem.UUID
	defaultDynamoDBUser := DefaultDynamoDBStoreUser{
		UserUniqueIdentifier: &uuid,
		DefaultPosixUser:     posixUser,
		EmailAddress:         &email,
	}
	return defaultDynamoDBUser, nil
}

func DefaultDynamoDBStoreUpdateUser(usr user.User, store *DefaultDynamoDBStore) error {
	ddbUser, ok := usr.(DefaultDynamoDBStoreUser)
	if !ok {
		log.Printf("The user passed %s does not implement Posix User interface. Cannot update user", *usr.GetPrincipalName())
		return fmt.Errorf("The user passed %s does not implement Posix User interface. Cannot update user", *usr.GetPrincipalName())
	}
	if ddbUser.UserUniqueIdentifier == nil {
		log.Printf("UUID is empty, cannot update user")
		return fmt.Errorf("UUID cannot be empty")
	}
	uuid := *ddbUser.UserUniqueIdentifier
	if ddbUser.GetPrincipalName() == nil {
		log.Printf("Principal Name is empty, cannot update user")
		return fmt.Errorf("Principal Name cannot be empty")
	}
	principalName := *ddbUser.GetPrincipalName()
	if ddbUser.GetUID() == nil {
		log.Printf("UID is empty, cannot update user")
		return fmt.Errorf("UID cannot be empty")
	}
	uid := *ddbUser.GetUID()
	if ddbUser.EmailAddress == nil {
		log.Printf("EmailAddress is empty, cannot update user")
		return fmt.Errorf("EmailAddress cannot be empty")
	}
	emailAddr := *ddbUser.EmailAddress

	secGroups := ddbUser.GetUserSecondaryGroups()
	var publicKey string
	if ddbUser.GetPublicKey() != nil {
		publicKeyBytes := ssh.MarshalAuthorizedKey(ddbUser.GetPublicKey())
		publicKey = string(publicKeyBytes)
	}

	userItem := Item{
		PK:        DDBUserRecordPKPrefix + principalName,
		SK:        DDBUserRecordSKPrefix + principalName,
		Name:      principalName,
		Email:     emailAddr,
		UUID:      uuid,
		Type:      DDBRecordTypeUserEnum,
		PosixId:   strconv.FormatUint(uint64(uid), 10),
		PublicKey: publicKey,
	}
	if ddbUser.GetPrimaryGroup().GetGroupName() != nil {
		userItem.UserPrimaryGroup = *ddbUser.GetPrimaryGroup().GetGroupName()
	}
	if ddbUser.GetPrimaryGroup().GetGroupID() != nil {
		userItem.UserPrimaryGroupPosixId = strconv.FormatUint(uint64(*ddbUser.GetPrimaryGroup().GetGroupID()), 10)
	}
	if latestPasswdHash, ok := usr.(user.UserLatestPasswdHash); ok && latestPasswdHash.GetLatestPasswdHash() != nil {
		userItem.PasswordHash = *latestPasswdHash.GetLatestPasswdHash()
	}
	if sudoClaims, ok := usr.(user.UserSudoClaims); ok {
		userItem.SudoClaims = sudoClaims.GetUserSudoClaims()
	}
	userSecGroupItems := make([]Item, 0)
	for _, group := range secGroups {
		if group.GetGroupName() == nil {
			log.Printf("Secondary Group's Name is empty, cannot update user")
			return fmt.Errorf("Secondary Group's Name cannot be empty")
		}
		secGrpName := *group.GetGroupName()
		if group.GetGroupID() == nil {
			log.Printf("Secondary Group's ID is empty, cannot update user")
			return fmt.Errorf("Secondary Group's ID cannot be empty")
		}
		secGrpID := *group.GetGroupID()
		userSecGroupItem := Item{
			PK:             DDBUserSecondaryGroupRecordPKPrefix + principalName,
			SK:             DDBUserSecondaryGroupRecordSKPrefix + secGrpName,
			PosixId:        strconv.FormatUint(uint64(secGrpID), 10),
			SecondaryGroup: secGrpName,
		}
		userSecGroupItems = append(userSecGroupItems, userSecGroupItem)
	}

	//check for UID vacancy here
	uidVacant, vacancyCheckErr := uidVacancyCheck(store.DDBClient, *store.TableName,
		*store.GSIPosixIDIndexName, userItem, true)
	if vacancyCheckErr != nil {
		log.Printf("UID vacancy checking failed while updating user %s", principalName)
		return fmt.Errorf("GID vacancy checking failed while updating user %s", principalName)
	}
	if !uidVacant {
		log.Printf("UID %d is not vacant to update user %s", uid, principalName)
		return fmt.Errorf("GID %d is not vacant to update group %s", uid, principalName)
	}

	updateUserErr := updateUserByUUID(store.DDBClient, *store.TableName, *store.GSIUUIDIndexName, userItem, userSecGroupItems)
	if updateUserErr != nil {
		log.Printf("Failed to update user with UUID %s - %+v", *ddbUser.UserUniqueIdentifier, updateUserErr)
		return fmt.Errorf("Failed to update user with UUID %s", *ddbUser.UserUniqueIdentifier)
	}
	return nil
}

func DefaultDynamoDBStoreDeleteUser(user user.User, store *DefaultDynamoDBStore) error {
	if user.GetPrincipalName() == nil {
		log.Printf("Principal Name is nil, cannot delete user")
		return fmt.Errorf("Principal Name cannot be empty")
	}
	usr := *user.GetPrincipalName()
	ddbTransactions, appendUserDelTransactionsErr := appendUserDeleteTransactions(store.DDBClient, *store.TableName, usr, make([]*dynamodb.TransactWriteItem, 0))
	if appendUserDelTransactionsErr != nil {
		log.Printf("Error occurred while appending transactions for deleting user %s - %+v", usr, appendUserDelTransactionsErr)
		return fmt.Errorf("Error occurred while appending transactions for deleting user %s", usr)
	}
	userDeleteTransactionInput := &dynamodb.TransactWriteItemsInput{
		TransactItems: ddbTransactions,
	}
	_, userDeleteTransactionErr := store.DDBClient.TransactWriteItems(userDeleteTransactionInput)
	if userDeleteTransactionErr != nil {
		switch t := userDeleteTransactionErr.(type) {
		case *dynamodb.TransactionCanceledException:
			if strings.Contains(t.Message(), "ConditionalCheckFailed") {
				log.Printf("No matching user found matching %s to delete. Dynamodb error - #%v", user, userDeleteTransactionErr)
				return fmt.Errorf("No matching user found matching %s to delete", user)
			} else {
				log.Printf("DynamoDB cancelled delete transaction while executing user delete transactions for user %s - #%v", user, userDeleteTransactionErr)
				return fmt.Errorf("DynamoDB cancelled delete transaction while executing user delete transactions for user %s", user)
			}
		default:
			log.Printf("DynamoDB returned error while executing user delete transactions for user %s - #%v", user, userDeleteTransactionErr)
			return fmt.Errorf("DynamoDB returned error while executing user delete transactions for user %s", user)
		}
	}
	return nil
}

func fetchUserByPK(client dynamodbiface.DynamoDBAPI, tblName string, userPrimaryKey map[string]string, userItem *Item) error {
	pk, err := dynamodbattribute.MarshalMap(userPrimaryKey)
	if err != nil {
		log.Printf("Failed to marshal primary key while fetching user for filter %+v", userPrimaryKey)
		return fmt.Errorf("Failed to marshal primary key while fetching user for filter %+v", userPrimaryKey)
	}
	proj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordNameKey),
		expression.Name(DDBRecordUUIDKey),
		expression.Name(DDBRecordEmailKey),
		expression.Name(DDBRecordCreatedKey),
		expression.Name(DDBRecordTypeKey),
		expression.Name(DDBRecordPosixIdKey),
		expression.Name(DDBRecordUserPrimaryGroupKey),
		expression.Name(DDBRecordPublicKeyKey),
		expression.Name(DDBRecordValidKey),
		expression.Name(DDBRecordUserPrimaryGroupPosixIdKey),
		expression.Name(DDBRecordUserSudoClaimsKey),
		expression.Name(DDBRecordUserPasswordHashKey),
	)
	expr, exprErr := expression.NewBuilder().WithProjection(proj).Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching user for filter %+v", userPrimaryKey)
		return fmt.Errorf("Failed to build DDB expression while fetching user for filter %+v", userPrimaryKey)
	}
	input := &dynamodb.GetItemInput{
		TableName:                aws.String(tblName),
		Key:                      pk,
		ExpressionAttributeNames: expr.Names(),
		ProjectionExpression:     expr.Projection(),
	}
	result, getItemErr := client.GetItem(input)
	if getItemErr != nil {
		log.Printf("Failed to get user for filter %+v from DDB", userPrimaryKey)
		return fmt.Errorf("Failed to get user for filter %+v from DDB", userPrimaryKey)
	}
	if result.Item != nil {
		if err := dynamodbattribute.UnmarshalMap(result.Item, userItem); err != nil {
			log.Printf("Failed to unmarshall result into user for filter %+v from DDB", userPrimaryKey)
			return fmt.Errorf("Failed to unmarshall result into user for filter %+v from DDB", userPrimaryKey)
		}
	}
	return nil
}

func fetchUserByGsi(client dynamodbiface.DynamoDBAPI, tblName string, indexName string, keyConditionBuilder expression.KeyConditionBuilder, usrItem *Item) error {
	proj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordNameKey),
		expression.Name(DDBRecordUUIDKey),
		expression.Name(DDBRecordEmailKey),
		expression.Name(DDBRecordCreatedKey),
		expression.Name(DDBRecordTypeKey),
		expression.Name(DDBRecordPosixIdKey),
		expression.Name(DDBRecordUserPrimaryGroupKey),
		expression.Name(DDBRecordPublicKeyKey),
		expression.Name(DDBRecordValidKey),
		expression.Name(DDBRecordUserPrimaryGroupPosixIdKey),
		expression.Name(DDBRecordUserSudoClaimsKey),
		expression.Name(DDBRecordUserPasswordHashKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(keyConditionBuilder).
		WithProjection(proj).
		Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching users for key condition %+v", keyConditionBuilder)
		return fmt.Errorf("Failed to build DDB expression while fetching users for key condition %+v", keyConditionBuilder)
	}
	usersQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(tblName),
		IndexName:                 aws.String(indexName),
		ProjectionExpression:      expr.Projection(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
	}
	usersQueryResult, usersQueryErr := client.Query(usersQueryInput)
	if usersQueryErr != nil {
		log.Printf("Error querying users for key condition %+v - %+v", keyConditionBuilder, usersQueryErr)
		return fmt.Errorf("Error querying users for key condition %+v", keyConditionBuilder)
	}
	if len(usersQueryResult.Items) > 1 {
		log.Printf("Found more than one matching user for key condition %+v", keyConditionBuilder)
		return fmt.Errorf("Found more than one matching user for key condition %+v", keyConditionBuilder)
	} else if len(usersQueryResult.Items) == 0 {
		log.Printf("Found no matching user for key condition %+v", keyConditionBuilder)
		return nil
	}
	if err := dynamodbattribute.UnmarshalMap(usersQueryResult.Items[0], usrItem); err != nil {
		log.Printf("Failed to unmarshall result into user for filter %+v", keyConditionBuilder)
		return fmt.Errorf("Failed to unmarshall result into user for filter %+v", keyConditionBuilder)
	}
	return nil
}

func appendUserSecondaryGroupsByUser(client dynamodbiface.DynamoDBAPI, tblName string, user string, userSecGroupItems []Item) ([]Item, error) {
	userSecGroupsCond := expression.KeyAnd(
		expression.Key(DDBRecordPK).Equal(expression.Value(DDBUserSecondaryGroupRecordPKPrefix+user)),
		expression.Key(DDBRecordSK).BeginsWith(DDBUserSecondaryGroupRecordSKPrefix),
	)
	userSecGroupsProj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordSecondaryGroupKey),
		expression.Name(DDBRecordPosixIdKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(userSecGroupsCond).
		WithProjection(userSecGroupsProj).
		Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching user sec groups for user record %s", user)
		return nil, fmt.Errorf("Failed to build DDB expression while fetching user sec groups for user record %s", user)
	}
	userSecGroupsQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(tblName),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}
	userSecGroupsQueryResult, userSecGroupsQueryErr := client.Query(userSecGroupsQueryInput)
	if userSecGroupsQueryErr != nil {
		log.Printf("Error querying secondary groups for user %s - %+v", user, userSecGroupsQueryErr)
		return nil, fmt.Errorf("Error querying secondary groups for user %s", user)
	}
	items := []Item{}
	if len(userSecGroupsQueryResult.Items) > 0 {
		if err := dynamodbattribute.UnmarshalListOfMaps(userSecGroupsQueryResult.Items, &items); err != nil {
			log.Printf("Failed to unmarshall user secondary group results for user %s - %+v", user, err)
			return nil, fmt.Errorf("Failed to unmarshall user secondary group results for user %s", user)
		}
		userSecGroupItems = append(userSecGroupItems, items...)
	}
	return userSecGroupItems, nil
}

func putUser(client dynamodbiface.DynamoDBAPI, tblName string, userItem Item, userSecGroupItems []Item, isUpdate bool) error {
	userName := strings.TrimPrefix(userItem.PK, DDBUserRecordPKPrefix)
	ddbTransactions := make([]*dynamodb.TransactWriteItem, 0)

	ddbTransactions, appendTransactionsErr := appendUserPutTransactions(client, tblName, userItem, userSecGroupItems, isUpdate, ddbTransactions)
	if appendTransactionsErr != nil {
		log.Printf("Error occurred while appending transactions for putting user %s - %+v", userName, appendTransactionsErr)
		return fmt.Errorf("Error occurred while appending transactions for putting user %s", userName)
	}

	userWriteTransactionInput := &dynamodb.TransactWriteItemsInput{
		TransactItems: ddbTransactions,
	}
	_, userWriteTransactionErr := client.TransactWriteItems(userWriteTransactionInput)
	if userWriteTransactionErr != nil {
		log.Printf("DynamoDB returned error while executing user write transactions for %s - #%v", userName, userWriteTransactionErr)
		return fmt.Errorf("DynamoDB returned error while executing user write transactions for %s", userName)
	}
	return nil
}

func uidVacancyCheck(client dynamodbiface.DynamoDBAPI, tblName string, gsiPosixIDIndex string,
	usrItem Item, isUpdate bool) (bool, error) {
	uidKeyConditionBuilder := expression.KeyAnd(
		expression.KeyEqual(expression.Key(DDBGsiPosixIDPK), expression.Value(usrItem.PosixId)),
		expression.KeyEqual(expression.Key(DDBGsiPosixIDSK), expression.Value(DDBRecordTypeUserEnum)))
	proj := expression.NamesList(
		expression.Name(DDBGsiPosixIDPK),
		expression.Name(DDBGsiPosixIDSK),
		expression.Name(DDBRecordUUIDKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(uidKeyConditionBuilder).
		WithProjection(proj).
		Build()
	if exprErr != nil {
		log.Print("Failed to build DDB expression while checking for uid vacancy")
		return false, fmt.Errorf("Failed to build DDB expression while checking for uid vacancy")
	}
	uidVacancyQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(tblName),
		IndexName:                 aws.String(gsiPosixIDIndex),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}
	uidVacancyQueryResult, uidVacancyQueryErr := client.Query(uidVacancyQueryInput)
	if uidVacancyQueryErr != nil {
		log.Printf("Error querying uid vacancy for key condition %+v", uidKeyConditionBuilder)
		return false, fmt.Errorf("Error querying uid vacancy for key condition %+v", uidKeyConditionBuilder)
	}
	if len(uidVacancyQueryResult.Items) == 0 {
		log.Printf("Found no matching uid entries for key condition %+v", uidKeyConditionBuilder)
		return true, nil
	} else if len(uidVacancyQueryResult.Items) == 1 {
		log.Printf("Found one matching uid entry for key condition %+v", uidKeyConditionBuilder)
		uidItem := Item{}
		if err := dynamodbattribute.UnmarshalMap(uidVacancyQueryResult.Items[0], &uidItem); err != nil {
			log.Printf("Failed to unmarshall result into uid item for filter %+v", uidKeyConditionBuilder)
			return false, fmt.Errorf("Failed to unmarshall result into uid item for filter %+v", uidKeyConditionBuilder)
		}
		if uidItem.UUID == usrItem.UUID && isUpdate {
			//this means the request is to update the same existing user without modifying the UID
			log.Printf("user update requested but uid has not changed")
			return true, nil
		} else {
			//this means either that the request is to update an existing user or
			// that the request is to add a new user. But the GID is already taken.
			log.Printf("The requested UID %s is already taken up", usrItem.PosixId)
			return false, nil
		}
	}
	log.Printf("Found more than one matching uid entries for key condition %+v", uidKeyConditionBuilder)
	return false, fmt.Errorf("Found more than one matching uid entries for key condition %+v", uidKeyConditionBuilder)
}

func updateUserByPrimaryKey(client dynamodbiface.DynamoDBAPI, tblName string, userItem Item, userSecGroupItems []Item) error {
	updateUserErr := putUser(client, tblName, userItem, userSecGroupItems, true)
	if updateUserErr != nil {
		log.Printf("Failed to update user %s - %+v", strings.TrimPrefix(userItem.PK, DDBUserRecordPKPrefix), updateUserErr)
		return fmt.Errorf("Failed to update user %s", strings.TrimPrefix(userItem.PK, DDBUserRecordPKPrefix))
	}
	return nil
}

func updateUserByUUID(client dynamodbiface.DynamoDBAPI, tblName string, gsiUUIDIndexName string, userItem Item, userSecGroupItems []Item) error {
	uuidItem := Item{}
	uuidKeyConditionBuilder := expression.KeyEqual(
		expression.Key(DDBGsiUUIDPK),
		expression.Value(userItem.UUID))
	fetchUserErr := fetchUserByGsi(client, tblName, gsiUUIDIndexName, uuidKeyConditionBuilder, &uuidItem)

	if fetchUserErr != nil {
		log.Printf("Error in locating user with UUID %s to update - %+v", userItem.UUID, fetchUserErr)
		return fmt.Errorf("Error in locating user with UUID %s to update", userItem.UUID)
	}
	if uuidItem.PK == "" {
		log.Printf("Failed to locate a user with UUID %s to update", userItem.UUID)
		return fmt.Errorf("Failed to locate a user with UUID %s to update", userItem.UUID)
	}
	if userItem.PK == "" {
		userItem.PK = uuidItem.PK
		userItem.SK = uuidItem.SK
		return updateUserByPrimaryKey(client, tblName, userItem, userSecGroupItems)
	} else {
		if userItem.PK == uuidItem.PK {
			return updateUserByPrimaryKey(client, tblName, userItem, userSecGroupItems)
		} else {
			ddbTransactions := make([]*dynamodb.TransactWriteItem, 0)
			deleteUserName := strings.TrimPrefix(uuidItem.PK, DDBUserRecordPKPrefix)
			ddbTransactions, appendUserDelTransactionsErr := appendUserDeleteTransactions(client, tblName, deleteUserName, ddbTransactions)
			if appendUserDelTransactionsErr != nil {
				log.Printf("Error occurred while appending transactions for deleting user %s - %+v", deleteUserName, appendUserDelTransactionsErr)
				return fmt.Errorf("Error occurred while appending transactions for deleting user %s", deleteUserName)
			}
			ddbTransactions, appendUserPutTransactionsErr := appendUserPutTransactions(client, tblName, userItem, userSecGroupItems, false, ddbTransactions)
			if appendUserPutTransactionsErr != nil {
				log.Printf("Error occurred while appending transactions for updating user with UUID %s - %+v", userItem.UUID, appendUserPutTransactionsErr)
				return fmt.Errorf("Error occurred while appending transactions for updating user with UUID %s", userItem.UUID)
			}
			userUpdateTransactionInput := &dynamodb.TransactWriteItemsInput{
				TransactItems: ddbTransactions,
			}
			_, userUpdateTransactionErr := client.TransactWriteItems(userUpdateTransactionInput)
			if userUpdateTransactionErr != nil {
				log.Printf("DynamoDB returned error while executing user update transactions for UUID %s - %+v", userItem.UUID, userUpdateTransactionErr)
				return fmt.Errorf("DynamoDB returned error while executing user update transactions for UUID %s", userItem.UUID)
			}
			return nil
		}
	}
}

func appendUserPutTransactions(client dynamodbiface.DynamoDBAPI, tblName string, userItem Item, userSecGroupItems []Item, isUpdate bool, ddbTransactions []*dynamodb.TransactWriteItem) ([]*dynamodb.TransactWriteItem, error) {
	userName := strings.TrimPrefix(userItem.PK, DDBUserRecordPKPrefix)
	putUserItem, marshalErr := dynamodbattribute.MarshalMap(userItem)
	if marshalErr != nil {
		log.Printf("Failed to marshal user item for user %s", userName)
		return nil, fmt.Errorf("Failed to marshal user item for user %s", userName)
	}
	userPut := &dynamodb.Put{
		Item:      putUserItem,
		TableName: aws.String(tblName),
	}
	if isUpdate {
		condition := expression.And(expression.AttributeExists(expression.Name(DDBRecordPK)), expression.AttributeExists(expression.Name(DDBRecordSK)))
		builder := expression.NewBuilder().WithCondition(condition)
		expr, buildErr := builder.Build()
		if buildErr != nil {
			log.Printf("Error occurred while build condition expression for ensuring existence of user - %+v", buildErr)
			return nil, fmt.Errorf("Error occurred while build condition expression for over-ruling existence of user - %+v", buildErr)
		}
		userPut.ConditionExpression = expr.Condition()
		userPut.ExpressionAttributeNames = expr.Names()
		userPut.ExpressionAttributeValues = expr.Values()
		//userPut.ConditionExpression = aws.String(fmt.Sprintf("(attribute_exists (%s)) AND (attribute_exists (%s))", DDBRecordPK, DDBRecordSK))
	} else {
		condition := expression.And(expression.AttributeNotExists(expression.Name(DDBRecordPK)),
			expression.AttributeNotExists(expression.Name(DDBRecordSK)))
		builder := expression.NewBuilder().WithCondition(condition)
		expr, buildErr := builder.Build()
		if buildErr != nil {
			log.Printf("Error occurred while build condition expression for over-ruling existence of user - %+v", buildErr)
			return nil, fmt.Errorf("Error occurred while build condition expression for over-ruling existence of user - %+v", buildErr)
		}
		userPut.ConditionExpression = expr.Condition()
		userPut.ExpressionAttributeNames = expr.Names()
		userPut.ExpressionAttributeValues = expr.Values()
		//userPut.ConditionExpression = aws.String(fmt.Sprintf("(attribute_not_exists (%s)) AND (attribute_not_exists (%s))", DDBRecordPK, DDBRecordSK))
	}
	putUserItemTransactWriteItem := &dynamodb.TransactWriteItem{
		Put: userPut,
	}
	ddbTransactions = append(ddbTransactions, putUserItemTransactWriteItem)

	if isUpdate {
		//append transactions to delete all current secondary groups associated with the user
		existingSecGroupItems, appendUserSecondaryGroupsErr := appendUserSecondaryGroupsByUser(client, tblName, userName, []Item{})
		if appendUserSecondaryGroupsErr != nil {
			log.Printf("Failed to fetch secondary groups of user %s - %+v", userName, appendUserSecondaryGroupsErr)
			return nil, fmt.Errorf("Failed to fetch existing secondary groups of user %s", userName)
		}
		userSecGroupItemsToDelete := make([]Item, 0)
		for _, existingSecGrp := range existingSecGroupItems {
			match := false
			for _, updatedSecGrp := range userSecGroupItems {
				if existingSecGrp.PK == updatedSecGrp.PK && existingSecGrp.SK == updatedSecGrp.SK {
					match = true
					break
				}
			}
			if match == false {
				userSecGroupItemsToDelete = append(userSecGroupItemsToDelete, existingSecGrp)
			}
		}
		for _, secGroupItem := range userSecGroupItemsToDelete {
			deleteSecGroupPrimaryKey := map[string]string{
				DDBRecordPK: secGroupItem.PK,
				DDBRecordSK: secGroupItem.SK,
			}
			deleteSecGroupMap, marshalErr := dynamodbattribute.MarshalMap(deleteSecGroupPrimaryKey)
			if marshalErr != nil {
				log.Printf("Failed to marshal primary key of user's SecGroup %+v", deleteSecGroupPrimaryKey)
				return nil, fmt.Errorf("Failed to marshal primary key of user's current SecGroup %+v", deleteSecGroupPrimaryKey)
			}
			secGroupDelete := &dynamodb.Delete{
				Key:       deleteSecGroupMap,
				TableName: aws.String(tblName),
			}
			deleteUserSecGroupTransactWriteItem := &dynamodb.TransactWriteItem{
				Delete: secGroupDelete,
			}
			ddbTransactions = append(ddbTransactions, deleteUserSecGroupTransactWriteItem)
		}
	}

	for _, item := range userSecGroupItems {
		secGroupItem := item
		groupName := strings.TrimPrefix(secGroupItem.SK, DDBUserSecondaryGroupRecordSKPrefix)
		groupId := secGroupItem.PosixId
		//condition check for group's existence
		groupRecordPrimaryKey := map[string]string{
			DDBRecordPK: DDBGroupRecordPKPrefix + groupName,
			DDBRecordSK: DDBGroupRecordSKPrefix + groupName,
		}
		primaryKey, err := dynamodbattribute.MarshalMap(groupRecordPrimaryKey)
		if err != nil {
			log.Printf("Failed to marshal group %s primary key attributes while checking group's existence", groupName)
			return nil, fmt.Errorf("Failed to marshal group %s primary key attributes while checking group's existence", groupName)
		}

		condition := expression.Equal(expression.Name(DDBRecordPosixIdKey), expression.Value(groupId))
		builder := expression.NewBuilder().WithCondition(condition)
		expr, buildErr := builder.Build()
		if buildErr != nil {
			log.Printf("Error occurred while build condition expression for validating existence of sec group - %+v", buildErr)
			return nil, fmt.Errorf("Error occurred while build condition expression for validating existence of sec group - %+v", buildErr)
		}
		groupExistsConditionCheck := &dynamodb.ConditionCheck{
			Key:                       primaryKey,
			TableName:                 aws.String(tblName),
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		}
		groupExistsConditionTransactionItem := &dynamodb.TransactWriteItem{
			ConditionCheck: groupExistsConditionCheck,
		}
		//log.Printf("%+v", groupExistsConditionTransactionItem)
		ddbTransactions = append(ddbTransactions, groupExistsConditionTransactionItem)

		//User secondary Group item put
		putUserSecGroupItem, marshalErr := dynamodbattribute.MarshalMap(secGroupItem)
		if marshalErr != nil {
			log.Printf("Failed to marshal user's secondary group item while creating user %s", userName)
			return nil, fmt.Errorf("Failed to marshal user's secondary group item while creating user %s", userName)
		}
		userSecGroupPut := &dynamodb.Put{
			Item:      putUserSecGroupItem,
			TableName: aws.String(tblName),
		}
		if !isUpdate {
			condition := expression.And(expression.AttributeNotExists(expression.Name(DDBRecordPK)), expression.AttributeNotExists(expression.Name(DDBRecordSK)))
			builder := expression.NewBuilder().WithCondition(condition)
			expr, buildErr := builder.Build()
			if buildErr != nil {
				log.Printf("Error occurred while build condition expression for over-ruling existence of user - %+v", buildErr)
				return nil, fmt.Errorf("Error occurred while build condition expression for over-ruling existence of user - %+v", buildErr)
			}
			userSecGroupPut.ConditionExpression = expr.Condition()
			userSecGroupPut.ExpressionAttributeNames = expr.Names()
			userSecGroupPut.ExpressionAttributeValues = expr.Values()
			//userSecGroupPut.ConditionExpression = aws.String(fmt.Sprintf("(attribute_not_exists (%s)) AND (attribute_not_exists (%s))", DDBRecordPK, DDBRecordSK))
		}
		putUserSecGroupItemTransactWriteItem := &dynamodb.TransactWriteItem{
			Put: userSecGroupPut,
		}
		ddbTransactions = append(ddbTransactions, putUserSecGroupItemTransactWriteItem)
	}
	return ddbTransactions, nil
}

func appendUserDeleteTransactions(client dynamodbiface.DynamoDBAPI, tblName string, user string, ddbTransactions []*dynamodb.TransactWriteItem) ([]*dynamodb.TransactWriteItem, error) {
	userSecGroupItems, appendUserSecondaryGroupsErr := appendUserSecondaryGroupsByUser(client, tblName, user, []Item{})
	if appendUserSecondaryGroupsErr != nil {
		log.Printf("Failed to fetch secondary groups of user %s - %+v", user, appendUserSecondaryGroupsErr)
		return nil, fmt.Errorf("Failed to fetch secondary groups of user %s", user)
	}

	deleteUserRecordPrimaryKey := map[string]string{
		DDBRecordPK: DDBUserRecordPKPrefix + user,
		DDBRecordSK: DDBUserRecordSKPrefix + user,
	}
	deleteUserMap, marshalErr := dynamodbattribute.MarshalMap(deleteUserRecordPrimaryKey)
	if marshalErr != nil {
		log.Printf("Failed to marshal primary key of user %+v", deleteUserRecordPrimaryKey)
		return nil, fmt.Errorf("Failed to marshal primary key of user %+v", deleteUserRecordPrimaryKey)
	}
	userDelete := &dynamodb.Delete{
		Key:                 deleteUserMap,
		TableName:           aws.String(tblName),
		ConditionExpression: aws.String(fmt.Sprintf("attribute_exists(%s) and attribute_exists(%s)", DDBRecordPK, DDBRecordSK)),
	}
	deleteUserItemTransactWriteItem := &dynamodb.TransactWriteItem{
		Delete: userDelete,
	}
	ddbTransactions = append(ddbTransactions, deleteUserItemTransactWriteItem)

	for _, secGroupItem := range userSecGroupItems {
		deleteSecGroupPrimaryKey := map[string]string{
			DDBRecordPK: secGroupItem.PK,
			DDBRecordSK: secGroupItem.SK,
		}
		deleteSecGroupMap, marshalErr := dynamodbattribute.MarshalMap(deleteSecGroupPrimaryKey)
		if marshalErr != nil {
			log.Printf("Failed to marshal primary key of user's SecGroup %+v", deleteSecGroupPrimaryKey)
			return nil, fmt.Errorf("Failed to marshal primary key of user's SecGroup %+v", deleteSecGroupPrimaryKey)
		}
		secGroupDelete := &dynamodb.Delete{
			Key:       deleteSecGroupMap,
			TableName: aws.String(tblName),
		}
		deleteUserSecGroupTransactWriteItem := &dynamodb.TransactWriteItem{
			Delete: secGroupDelete,
		}
		ddbTransactions = append(ddbTransactions, deleteUserSecGroupTransactWriteItem)
	}
	return ddbTransactions, nil
}

func (c *DefaultDynamoDBStoreUser) UnmarshalJSON(b []byte) error {
	type User struct {
		PrincipalName    *string                    `json:"principalName,omitempty"`
		UID              *uint32                    `json:"uid,omitempty"`
		PublicKey        json.RawMessage            `json:"publicKey,omitempty"`
		PrimaryGroup     *group.DefaultPosixGroup   `json:"primaryGroup,omitempty"`
		SecondaryGroups  []*group.DefaultPosixGroup `json:"secondaryGroups,omitempty"`
		LatestPasswdHash *string                    `json:"latestPasswdHash,omitempty"`
		SudoClaims       []string                   `json:"sudoClaims,omitempty"`
	}
	type StoreUser struct {
		UserUniqueIdentifier *string `json:"uuid,omitempty"`
		EmailAddress         *string `json:"email,omitempty"`
		User
	}

	user := User{}
	storeUser := StoreUser{User: user}
	unMarshalerr := json.Unmarshal(b, &storeUser)
	if unMarshalerr != nil {
		log.Printf("Failed to unmarshal user input json to a valid object - %+v", unMarshalerr)
		return fmt.Errorf("Failed to unmarshal user input json to a valid object - %+v", unMarshalerr)
	}

	c.UserUniqueIdentifier = storeUser.UserUniqueIdentifier
	c.EmailAddress = storeUser.EmailAddress
	c.PrincipalName = storeUser.PrincipalName
	c.UID = storeUser.UID
	if storeUser.PrimaryGroup != nil {
		c.PrimaryGroup = storeUser.PrimaryGroup
	}
	for _, each := range storeUser.SecondaryGroups {
		c.SecondaryGroups = append(c.SecondaryGroups, each)
	}
	c.LatestPasswdHash = storeUser.LatestPasswdHash
	c.SudoClaims = storeUser.SudoClaims

	if storeUser.PublicKey != nil {
		var pubKeyString string
		err := json.Unmarshal(storeUser.PublicKey, &pubKeyString)
		if err != nil {
			log.Printf("Failed to unmarshal public key from user input json - %+v", err)
			return fmt.Errorf("Failed to unmarshal public key from user input json - %+v", err)
		}
		if pubKeyString != "" {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyString))
			if err != nil {
				log.Printf("Failed to parse certificate from the string provided %s - %+v", pubKeyString, err)
				return fmt.Errorf("Failed to parse certificate from the string provided %s", pubKeyString)
			}
			c.PublicKey = pub
		} else {
			log.Print("Public Key string passed is empty, will be set to empty in the DB.")
		}
	}

	/*
		var generic map[string]interface{}
		err := json.Unmarshal(b, &generic)
		if err != nil {
			log.Printf("Failed to unmarshal json to a valid object - %+v", err)
			return fmt.Errorf("Failed to unmarshal json to a valid object - %+v", err)
		}

		if x, found := generic["uuid"]; found {
			var uuid string
			var ok bool
			if uuid, ok = x.(string); !ok {
				log.Printf("uuid field in JSON is not a valid string - %+v", x)
				return fmt.Errorf("uuid field in JSON is not a valid string")
			}
			c.UserUniqueIdentifier = &uuid
		} else {
			log.Print("uuid field is not present in the JSON")
		}

		if x, found := generic["email"]; found {
			var email string
			var ok bool
			if email, ok = x.(string); !ok {
				log.Printf("email field in JSON is not a valid string - %+v", x)
				return fmt.Errorf("email field in JSON is not a valid string")
			}
			c.EmailAddress = &email
		} else {
			log.Print("email field is not present in the JSON")
		}

		a := c.DefaultPosixUser

		if x, found := generic["principalName"]; found {
			var principalName string
			var ok bool
			if principalName, ok = x.(string); !ok {
				log.Printf("PrincipalName field in JSON is not a valid string - %+v", x)
				return fmt.Errorf("PrincipalName field in JSON is not a valid string")
			}
			a.SetPrincipalName(&principalName)
		} else {
			log.Print("PrincipalName field is not present in the JSON")
		}

		if x, found := generic["uid"]; found {
			if uid, ok := x.(int); !ok {
				log.Printf("uid parameter is not passed as a JSON number")
				var uidS string
				if uidS, ok = x.(string); !ok {
					log.Printf("uid field in JSON is not passed as string either - %+v", x)
					return fmt.Errorf("uid field in JSON is not passed as string or int")
				}
				uid, err := strconv.Atoi(uidS)
				if err != nil {
					log.Printf("uid field value could not be cast to integer - %+v", x)
					return fmt.Errorf("uid field value could not be cast to integer")
				}
				uid32 := uint32(uid)
				a.SetUID(&uid32)
			} else {
				uid32 := uint32(uid)
				a.SetUID(&uid32)
			}
		} else {
			log.Print("uid field is not present in the JSON")
		}

		if x, found := generic["publicKey"]; found {
			var pubKeyString string
			var ok bool
			if pubKeyString, ok = x.(string); !ok {
				log.Printf("publicKey field in JSON is not a valid string - %+v", x)
				return fmt.Errorf("publicKey field in JSON is not a valid string")
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyString))
			if err != nil {
				log.Printf("Failed to parse certificate from the string provided %s - %+v", pubKeyString, err)
				return fmt.Errorf("Failed to parse certificate from the string provided %s", pubKeyString)
			}
			pubKey, err := ssh.ParsePublicKey(pub.Marshal())
			if err != nil {
				log.Printf("Failed to parse public key from SSH wire format - %+v", err)
				return fmt.Errorf("Failed to parse public key from SSH wire format")
			}
			a.SetPublicKey(pubKey)
		} else {
			log.Print("publicKey field is not present in the JSON")
		}

		if x, found := generic["primaryGroup"]; found {
			primaryGrp, ok := x.(map[string]interface{})
			if !ok {
				log.Printf("primaryGroup field not passed as a map")
				return fmt.Errorf("primaryGroup field in JSON could not be mapped to a group")
			}
			var defaultPosixGrp group.DefaultPosixGroup

			if err := json.Unmarshal(primaryGrp, &defaultPosixGrp); err != nil {
				log.Printf("primaryGroup field in JSON could not be unmarshalled to DefaultPosixGroup - %+v", err)
				return fmt.Errorf("primaryGroup field in JSON could not be unmarshalled to DefaultPosixGroup")
			}
			a.SetPrimaryGroup(&defaultPosixGrp)
		} else {
			log.Print("primaryGroup field is not present in the JSON")
		}

		if x, found := generic["secondaryGroups"]; found {
			secGroupBytes, _ := x.(json.RawMessage)
			var secondaryGroups []DefaultDynamoDBStoreGroup
			if err := json.Unmarshal(secGroupBytes, &secondaryGroups); err != nil {
				log.Printf("secondaryGroups field in JSON could not be unmarshalled to DefaultPosixGroup slice - %+v", err)
				return fmt.Errorf("secondaryGroups field in JSON could not be unmarshalled to DefaultPosixGroup slice")
			}
			secGroups := make([]group.PosixGroup, 0)
			for _, grp := range secondaryGroups {
				secGroups = append(secGroups, &grp)
			}
			a.SetUserSecondaryGroups(secGroups)
		} else {
			log.Print("secondaryGroups field is not present in the JSON")
		}

		if x, found := generic["latestPasswdHash"]; found {
			var passwdHash string
			var ok bool
			if passwdHash, ok = x.(string); !ok {
				log.Printf("LatestPasswdHash field in JSON is not a valid string - %+v", x)
				return fmt.Errorf("LatestPasswdHash field in JSON is not a valid string")
			}
			a.SetLatestPasswdHash(&passwdHash)
		} else {
			log.Print("LatestPasswdHash field is not present in the JSON")
		}

		if x, found := generic["sudoClaims"]; found {
			var sudoClaims []string
			var ok bool
			if sudoClaims, ok = x.([]string); !ok {
				log.Printf("sudoClaims field in JSON is not a valid string list - %+v", x)
				return fmt.Errorf("sudoClaims field in JSON is not a valid string list")
			}
			a.SetUserSudoClaims(sudoClaims)
		} else {
			log.Print("sudoClaims field is not present in the JSON")
		}
	*/
	return nil
}

func (a DefaultDynamoDBStoreUser) MarshalJSON() ([]byte, error) {

	var pubKeyString string
	if pubKey := a.GetPublicKey(); pubKey != nil {
		pubKeyString = string(ssh.MarshalAuthorizedKey(pubKey))
	} else {
		pubKeyString = ""
	}

	primaryGroup, ok := a.GetPrimaryGroup().(*group.DefaultPosixGroup)
	if !ok {
		log.Printf("primaryGroup of user does not implement DefaultPosixGroup - %+v", primaryGroup)
		return nil, fmt.Errorf("primaryGroup of user does not implement DefaultPosixGroup")
	}

	secGroups := make([]group.DefaultPosixGroup, 0)
	for _, grp := range a.GetUserSecondaryGroups() {
		secGroup, ok := grp.(*group.DefaultPosixGroup)
		if !ok {
			log.Printf("secondaryGroup %+v of user does not implement DefaultPosixGroup", primaryGroup)
			return nil, fmt.Errorf("secondaryGroup of user does not implement DefaultPosixGroup")
		}
		secGroups = append(secGroups, *secGroup)
	}
	var email, uuid string
	if a.EmailAddress != nil {
		email = *a.EmailAddress
	}
	if a.UserUniqueIdentifier != nil {
		uuid = *a.UserUniqueIdentifier
	}
	return json.Marshal(&struct {
		UserUniqueIdentifier string                    `json:"uuid,omitempty"`
		EmailAddress         string                    `json:"email,omitempty"`
		PrincipalName        string                    `json:"principalName,omitempty"`
		UID                  uint32                    `json:"uid,omitempty"`
		PublicKey            string                    `json:"publicKey,omitempty"`
		PrimaryGroup         group.DefaultPosixGroup   `json:"primaryGroup,omitempty"`
		SecondaryGroups      []group.DefaultPosixGroup `json:"secondaryGroups,omitempty"`
		LatestPasswdHash     string                    `json:"latestPasswdHash,omitempty"`
		SudoClaims           []string                  `json:"sudoClaims,omitempty"`
	}{
		UserUniqueIdentifier: uuid,
		EmailAddress:         email,
		PrincipalName:        *a.GetPrincipalName(),
		UID:                  *a.GetUID(),
		PublicKey:            pubKeyString,
		PrimaryGroup:         *primaryGroup,
		SecondaryGroups:      secGroups,
		LatestPasswdHash:     *a.GetLatestPasswdHash(),
		SudoClaims:           a.GetUserSudoClaims(),
	})
}
