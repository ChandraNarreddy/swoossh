package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/google/uuid"
)

type DefaultStoreGroupFilter struct {
	GroupNameProjection             *string
	GroupIDProjection               *string
	GroupUniqueIdentifierProjection *string
}

type DefaultStoreGroupSearchFilter struct {
	GroupNameSearchProjection *string
	PageToken                 *string
	PageSize                  *int
	Order                     *DDBQueryOrder
}

type DefaultDynamoDBStoreGroup struct {
	GroupUniqueIdentifier *string `json:"uuid,omitempty"`
	*group.DefaultPosixGroup
}

func (c *DefaultDynamoDBStoreGroup) GetGroup() group.Group {
	return c
}

type DefaultStoreGroupSearchResponse struct {
	Result            []*DefaultDynamoDBStoreGroup
	NextPageToken     *string
	PreviousPageToken *string
}

func (c *DefaultStoreGroupSearchResponse) GetGroupSearchResults() []GroupSearchResult {
	if len(c.Result) == 0 {
		return nil
	}
	result := make([]GroupSearchResult, 0)
	for _, each := range c.Result {
		result = append(result, each)
	}
	return result
}

func DefaultDynamoDBStoreSearchGroups(filter GroupFilter, store *DefaultDynamoDBStore) (GroupSearchResp, error) {
	groupFilter, ok := filter.(*DefaultStoreGroupSearchFilter)
	if !ok {
		log.Print("Group Filter passed could not be cast to DefaultStoreGroupSearchFilter")
		return nil, fmt.Errorf("Group Filter passed could not be cast to DefaultStoreGroupSearchFilter")
	}
	var nameSearchFilter string
	if groupFilter.GroupNameSearchProjection != nil {
		nameSearchFilter = *groupFilter.GroupNameSearchProjection
	} else {
		log.Print("Group filter passed does not contain a search projection, can't continue")
		return nil, fmt.Errorf("Group filter passed does not contain a search projection")
	}
	groupNameKeyConditionBuilder := expression.KeyAnd(
		expression.Key(DDBGsiTypePK).Equal(expression.Value(DDBRecordTypeGroupEnum)),
		expression.Key(DDBGsiTypeSK).BeginsWith(DDBGroupRecordPKPrefix+nameSearchFilter),
	)
	proj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordNameKey),
		expression.Name(DDBRecordUUIDKey),
		expression.Name(DDBRecordCreatedKey),
		expression.Name(DDBRecordTypeKey),
		expression.Name(DDBRecordPosixIdKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(groupNameKeyConditionBuilder).
		WithProjection(proj).
		Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching groups for key condition %+v", groupNameKeyConditionBuilder)
		return nil, fmt.Errorf("Failed to build DDB expression while fetching group for key condition %+v", groupNameKeyConditionBuilder)
	}
	groupsQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(*store.TableName),
		IndexName:                 aws.String(*store.GSITypeIndexName),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}
	if groupFilter.Order != nil {
		if *groupFilter.Order == DDBQueryOrderReverse {
			fal := false
			groupsQueryInput.ScanIndexForward = &fal
		}
	}
	var size *int64
	if groupFilter.PageSize != nil {
		tmp := int64(*groupFilter.PageSize)
		size = &tmp
	}

	var exclusiveStartKey, lastEvaluatedKey map[string]*dynamodb.AttributeValue
	if groupFilter.PageToken != nil {
		var decodeTokenErr error
		exclusiveStartKey, decodeTokenErr = decodePageToken(*groupFilter.PageToken)
		if decodeTokenErr != nil {
			log.Printf("Failure in decoding page token for key condition %+v", groupNameKeyConditionBuilder)
			return nil, fmt.Errorf("Failure in decoding page token for key condition %+v", groupNameKeyConditionBuilder)
		}
	}

	groupResults := make([]*DefaultDynamoDBStoreGroup, 0)
	var lastEvaluatedKeyEncodedToken string
	var firstEvaluatedKeyEncodedToken string
	for i := 0; ; {
		if size != nil {
			groupsQueryInput.Limit = size
		}
		if exclusiveStartKey != nil {
			groupsQueryInput.ExclusiveStartKey = exclusiveStartKey
		}
		groupsQueryResult, groupsQueryErr := store.DDBClient.Query(groupsQueryInput)
		if groupsQueryErr != nil {
			log.Printf("Error querying groups for key condition %+v - %+v", groupNameKeyConditionBuilder, groupsQueryErr)
			return nil, fmt.Errorf("Error querying groups for key condition %+v", groupNameKeyConditionBuilder)
		}
		if len(groupsQueryResult.Items) > 0 {
			groupItems := []Item{}
			if err := dynamodbattribute.UnmarshalListOfMaps(groupsQueryResult.Items, &groupItems); err != nil {
				log.Printf("Failed to unmarshall group results for key condition %+v", groupNameKeyConditionBuilder)
				continue
			}
			for _, item := range groupItems {
				grp := strings.TrimPrefix(item.PK, DDBGroupRecordPKPrefix)
				grpPosixId, parseErr := strconv.ParseUint(item.PosixId, 10, 16)
				if parseErr != nil {
					log.Printf("Failed to parse posix id %s of group %s", item.PosixId, grp)
				}
				grpPosixId16 := uint16(grpPosixId)
				posixGroup := &group.DefaultPosixGroup{
					Gid:  &grpPosixId16,
					Name: &grp,
				}
				uuid := item.UUID
				defaultDynamoDBGroup := DefaultDynamoDBStoreGroup{
					GroupUniqueIdentifier: &uuid,
					DefaultPosixGroup:     posixGroup,
				}
				if groupFilter.Order != nil {
					if *groupFilter.Order == DDBQueryOrderReverse {
						groupResults = append([]*DefaultDynamoDBStoreGroup{&defaultDynamoDBGroup}, groupResults...)
					} else {
						groupResults = append(groupResults, &defaultDynamoDBGroup)
					}
				} else {
					groupResults = append(groupResults, &defaultDynamoDBGroup)
				}
			}
			if i == 0 {
				firstEvaluatedResult := Item{
					PK:   groupItems[0].PK,
					SK:   groupItems[0].SK,
					Type: groupItems[0].Type,
				}
				firstEvaluatedResultItem, marshalErr := dynamodbattribute.MarshalMap(firstEvaluatedResult)
				if marshalErr != nil {
					log.Printf("Failed to marshal firstEvaluatedResult - %+v", marshalErr)
					return nil, fmt.Errorf("Failed to marshal firstEvaluatedResult - %+v", marshalErr)
				}
				var encodeErr error
				firstEvaluatedKeyEncodedToken, encodeErr = encodeLastEvaluatedKey(firstEvaluatedResultItem)
				if encodeErr != nil {
					log.Printf("Failed to encode first result item for key condition %+v - %+v", groupNameKeyConditionBuilder, encodeErr)
					return nil, fmt.Errorf("Failed to encode first result item for key condition %+v", groupNameKeyConditionBuilder)
				}
			}
		}
		if len(groupsQueryResult.LastEvaluatedKey) != 0 {
			if int64(len(groupsQueryResult.Items)) == *size {
				lastEvaluatedKey = groupsQueryResult.LastEvaluatedKey
				var encodeErr error
				lastEvaluatedKeyEncodedToken, encodeErr = encodeLastEvaluatedKey(lastEvaluatedKey)
				if encodeErr != nil {
					log.Printf("Failed to encode lastEvaluatedKey for key condition %+v - %+v", groupNameKeyConditionBuilder, encodeErr)
					return nil, fmt.Errorf("Failed to encode lastEvaluatedKey for key condition %+v", groupNameKeyConditionBuilder)
				}
				break
			} else {
				tmp := *size - int64(len(groupsQueryResult.Items))
				size = &tmp
				exclusiveStartKey = groupsQueryResult.LastEvaluatedKey
			}
		} else {
			break
		}
	}
	if len(groupResults) == 0 {
		log.Printf("No groups found for key condition %+v", groupNameKeyConditionBuilder)
		resp := &DefaultStoreGroupSearchResponse{
			Result:            nil,
			NextPageToken:     nil,
			PreviousPageToken: nil,
		}
		return resp, nil
	}

	resp := &DefaultStoreGroupSearchResponse{
		Result:            groupResults,
		NextPageToken:     &lastEvaluatedKeyEncodedToken,
		PreviousPageToken: &firstEvaluatedKeyEncodedToken,
	}

	if groupFilter.Order != nil && *groupFilter.Order == DDBQueryOrderReverse {
		resp.NextPageToken = &firstEvaluatedKeyEncodedToken
		resp.PreviousPageToken = &lastEvaluatedKeyEncodedToken
	}
	return resp, nil
}

func DefaultDynamoDBStoreCreateGroup(group group.Group, store *DefaultDynamoDBStore) error {
	ddbGroup, ok := group.(DefaultDynamoDBStoreGroup)
	if !ok {
		log.Printf("The group passed %s does not implement Posix Group interface. Cannot add group", *group.GetGroupName())
		return fmt.Errorf("The user passed %s does not implement Posix Group interface. Cannot add group", *group.GetGroupName())
	}
	if ddbGroup.GetGroupName() == nil {
		log.Printf("Group name is empty, cannot add group")
		return fmt.Errorf("Group name cannot be empty")
	}
	grpName := *ddbGroup.GetGroupName()
	if ddbGroup.GetGroupID() == nil {
		log.Printf("Group ID is empty, cannot add group")
		return fmt.Errorf("Group ID cannot be empty")
	}
	grpID := *ddbGroup.GetGroupID()
	uuid, uuidErr := uuid.NewRandom()
	if uuidErr != nil {
		log.Printf("Failed to generate uuid while creating group %s", grpName)
		return fmt.Errorf("Failed to generate uuid while creating group %s", grpName)
	}
	uuidStr := uuid.String()
	groupItem := Item{
		PK:      DDBGroupRecordPKPrefix + grpName,
		SK:      DDBGroupRecordSKPrefix + grpName,
		Name:    grpName,
		UUID:    uuidStr,
		Created: time.Now().Format(time.RFC3339),
		Type:    DDBRecordTypeGroupEnum,
		PosixId: strconv.FormatUint(uint64((grpID)), 10),
	}

	//check gid vacancy here
	gidVacant, vacancyCheckErr := gidVacancyCheck(store.DDBClient, *store.TableName,
		*store.GSIPosixIDIndexName, groupItem, false)
	if vacancyCheckErr != nil {
		log.Printf("GID vacancy checking failed while creating group %s", grpName)
		return fmt.Errorf("GID vacancy checking failed while creating group %s", grpName)
	}
	if !gidVacant {
		log.Printf("GID %d is not vacant to create group %s", grpID, grpName)
		return fmt.Errorf("GID %d is not vacant to create group %s", grpID, grpName)
	}

	putGroupErr := putGroup(store.DDBClient, *store.TableName, groupItem, false)
	if putGroupErr != nil {
		log.Printf("Failed to create group %s - %+v", *ddbGroup.GetGroupName(), putGroupErr)
		return fmt.Errorf("Failed to create group %s", *ddbGroup.GetGroupName())
	}
	return nil
}

func DefaultDynamoDBStoreGetGroup(filter GroupFilter, store *DefaultDynamoDBStore) (group.Group, error) {
	grpFilter, ok := filter.(*DefaultStoreGroupFilter)
	if !ok {
		log.Print("User Filter passed could not be cast to DefaultStoreGroupFilter")
		return nil, fmt.Errorf("User Filter passed could not be cast to DefaultStoreGroupFilter")
	}
	grpItem := Item{}
	if grpFilter.GroupNameProjection != nil {
		grpPrimaryKey := map[string]string{
			DDBRecordPK: DDBGroupRecordPKPrefix + *grpFilter.GroupNameProjection,
			DDBRecordSK: DDBGroupRecordSKPrefix + *grpFilter.GroupNameProjection,
		}
		fetchGroupErr := fetchGroupByPK(store.DDBClient, *store.TableName, grpPrimaryKey, &grpItem)
		if fetchGroupErr != nil {
			log.Printf("Failure in fetching group for filter %+v - %+v", *grpFilter.GroupNameProjection, fetchGroupErr)
			return nil, fmt.Errorf("Failure in fetching user for filter %+v", *grpFilter.GroupNameProjection)
		}
	}
	if grpFilter.GroupUniqueIdentifierProjection != nil && grpItem.PK == "" {
		uuidKeyConditionBuilder := expression.KeyEqual(expression.Key(DDBGsiUUIDPK), expression.Value(*(grpFilter.GroupUniqueIdentifierProjection)))
		fetchGroupErr := fetchGroupByGsi(store.DDBClient, *store.TableName, *store.GSIUUIDIndexName, uuidKeyConditionBuilder, &grpItem)
		if fetchGroupErr != nil {
			log.Printf("Failure in fetching group for filter %+v - %+v", *(grpFilter.GroupUniqueIdentifierProjection), fetchGroupErr)
			return nil, fmt.Errorf("Failure in fetching group for filter %+v", *(grpFilter.GroupUniqueIdentifierProjection))
		}
	}
	if grpFilter.GroupIDProjection != nil && grpItem.PK == "" {
		posixIdKeyConditionBuilder := expression.KeyAnd(
			expression.KeyEqual(expression.Key(DDBGsiPosixIDPK), expression.Value(*(grpFilter.GroupIDProjection))),
			expression.KeyEqual(expression.Key(DDBGsiPosixIDSK), expression.Value(DDBRecordTypeGroupEnum)))
		fetchGroupErr := fetchGroupByGsi(store.DDBClient, *store.TableName, *store.GSIPosixIDIndexName, posixIdKeyConditionBuilder, &grpItem)
		if fetchGroupErr != nil {
			log.Printf("Failure in fetching group for filter %+v - %+v", *(grpFilter.GroupIDProjection), fetchGroupErr)
			return nil, fmt.Errorf("Failure in fetching group for filter %+v", *(grpFilter.GroupIDProjection))
		}
	}
	if grpItem.PK == "" {
		log.Print("Found no group record for the filters passed")
		return nil, nil
	}
	grp := strings.TrimPrefix(grpItem.PK, DDBGroupRecordPKPrefix)
	grpPosixId, parseErr := strconv.ParseUint(grpItem.PosixId, 10, 16)
	if parseErr != nil {
		log.Printf("Failed to parse posix id %s of group %s", grpItem.PosixId, grp)
		return nil, fmt.Errorf("Failed to parse posix id %s of group %s", grpItem.PosixId, grp)
	}
	grpPosixId16 := uint16(grpPosixId)
	posixGroup := &group.DefaultPosixGroup{
		Gid:  &grpPosixId16,
		Name: &grp,
	}
	defaultDynamoDBGroup := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: &grpItem.UUID,
		DefaultPosixGroup:     posixGroup,
	}
	return defaultDynamoDBGroup, nil
}

func DefaultDynamoDBStoreUpdateGroup(group group.Group, store *DefaultDynamoDBStore) error {
	ddbGroup, ok := group.(DefaultDynamoDBStoreGroup)
	if !ok {
		log.Printf("The group passed %s does not implement Posix Group interface. Cannot add group", *group.GetGroupName())
		return fmt.Errorf("The user passed %s does not implement Posix Group interface. Cannot add group", *group.GetGroupName())
	}
	if ddbGroup.GetGroupName() == nil {
		log.Printf("Group name is empty, cannot update group")
		return fmt.Errorf("Group name cannot be empty")
	}
	grpName := *ddbGroup.GetGroupName()
	if ddbGroup.GetGroupID() == nil {
		log.Printf("Group ID is empty, cannot update group")
		return fmt.Errorf("Group ID cannot be empty")
	}
	grpID := *ddbGroup.GetGroupID()
	if ddbGroup.GroupUniqueIdentifier == nil {
		log.Printf("UUID is empty, cannot update group")
		return fmt.Errorf("UUID cannot be empty")
	}
	uuid := *ddbGroup.GroupUniqueIdentifier
	groupItem := Item{
		PK:      DDBGroupRecordPKPrefix + grpName,
		SK:      DDBGroupRecordSKPrefix + grpName,
		Name:    grpName,
		UUID:    uuid,
		Type:    DDBRecordTypeGroupEnum,
		PosixId: strconv.FormatUint(uint64((grpID)), 10),
	}
	//check gid vacancy here
	gidVacant, vacancyCheckErr := gidVacancyCheck(store.DDBClient, *store.TableName,
		*store.GSIPosixIDIndexName, groupItem, true)
	if vacancyCheckErr != nil {
		log.Printf("GID vacancy checking failed while updating group %s", grpName)
		return fmt.Errorf("GID vacancy checking failed while updating group %s", grpName)
	}
	if !gidVacant {
		log.Printf("GID %d is not vacant to update group %s", grpID, grpName)
		return fmt.Errorf("GID %d is not vacant to update group %s", grpID, grpName)
	}

	updateGroupErr := updateGroupByUUID(store.DDBClient, *store.TableName, *store.GSIUUIDIndexName, *store.GSISecondaryGroupIndexName, groupItem)
	if updateGroupErr != nil {
		log.Printf("Failed to update user with UUID %s - %+v", *ddbGroup.GroupUniqueIdentifier, updateGroupErr)
		return fmt.Errorf("Failed to update user with UUID %s", *ddbGroup.GroupUniqueIdentifier)
	}
	return nil
}

func DefaultDynamoDBStoreDeleteGroup(group group.Group, store *DefaultDynamoDBStore) error {
	if group.GetGroupName() == nil {
		log.Printf("Group Name is nil, cannot delete user")
		return fmt.Errorf("Group Name cannot be empty")
	}
	grp := *group.GetGroupName()
	/*
		ddbTransactions, appendGroupDelTransactionsErr := appendGroupDeleteTransactions(store.DDBClient, *store.TableName, grp, make([]*dynamodb.TransactWriteItem, 0))
		if appendGroupDelTransactionsErr != nil {
			log.Printf("Error occurred while appending transactions for deleting group %s - %+v", grp, appendGroupDelTransactionsErr)
			return fmt.Errorf("Error occurred while appending transactions for deleting group %s", grp)
		}
		groupDeleteTransactionInput := &dynamodb.TransactWriteItemsInput{
			TransactItems:               ddbTransactions,
			ReturnItemCollectionMetrics: aws.String("SIZE"),
		}
		output, groupDeleteTransactionErr := store.DDBClient.TransactWriteItems(groupDeleteTransactionInput)
		if groupDeleteTransactionErr != nil {
			log.Printf("DynamoDB returned error while executing group delete transactions for group %s - #%v", grp, groupDeleteTransactionErr)
			return fmt.Errorf("DynamoDB returned error while executing group delete transactions for group %s", grp)
		}
	*/
	deleteGroupRecordPrimaryKey := map[string]string{
		DDBRecordPK: DDBGroupRecordPKPrefix + grp,
		DDBRecordSK: DDBGroupRecordSKPrefix + grp,
	}
	deleteGroupMap, marshalErr := dynamodbattribute.MarshalMap(deleteGroupRecordPrimaryKey)
	if marshalErr != nil {
		log.Printf("Failed to marshal primary key of group %+v", deleteGroupRecordPrimaryKey)
		return fmt.Errorf("Failed to marshal primary key of group %+v", deleteGroupRecordPrimaryKey)
	}
	condExpression := fmt.Sprintf("attribute_exists(%s) and attribute_exists(%s)", DDBRecordPK, DDBRecordSK)
	groupDeleteInput := &dynamodb.DeleteItemInput{
		Key:                 deleteGroupMap,
		TableName:           aws.String(*store.TableName),
		ConditionExpression: aws.String(condExpression),
	}
	var noGrpsMatched bool
	_, deleteErr := store.DDBClient.DeleteItem(groupDeleteInput)
	if deleteErr != nil {
		if aerr, ok := deleteErr.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				log.Printf("Delete group condition check failed. No groups matching criteria")
				noGrpsMatched = true
			default:
				log.Printf("DynamoDB returned error while executing group delete transactions for group %s - #%v", grp, deleteErr)
				return fmt.Errorf("DynamoDB returned error while executing group delete transactions for group %s", grp)
			}
		}
	}
	secGrpsDeleted, err := deleteSecondaryGroups(store.DDBClient, *store.TableName, *store.GSISecondaryGroupIndexName, grp)
	if err != nil {
		return err
	}
	if noGrpsMatched && secGrpsDeleted == 0 {
		log.Print("No groups or secondary groups found matching the deletion criteria")
		return fmt.Errorf("No group or secondary groups found matching the criteria %s", grp)
	}
	return nil
}

func putGroup(client dynamodbiface.DynamoDBAPI, tblName string, grpItem Item, isUpdate bool) error {
	grpName := strings.TrimPrefix(grpItem.PK, DDBGroupRecordPKPrefix)
	ddbTransactions, appendTransactionsErr := appendGroupPutTransactions(tblName, grpItem, isUpdate, make([]*dynamodb.TransactWriteItem, 0))
	if appendTransactionsErr != nil {
		log.Printf("Error occurred while appending transactions for creating group %s - %+v", grpName, appendTransactionsErr)
		return fmt.Errorf("Error occurred while appending transactions for for creating group %s", grpName)
	}
	grpWriteTransactionInput := &dynamodb.TransactWriteItemsInput{
		TransactItems: ddbTransactions,
	}
	_, grpWriteTransactionErr := client.TransactWriteItems(grpWriteTransactionInput)
	if grpWriteTransactionErr != nil {
		log.Printf("DynamoDB returned error while executing group write transactions for %s - #%v", grpName, grpWriteTransactionErr)
		return fmt.Errorf("DynamoDB returned error while executing group write transactions for %s", grpName)
	}
	return nil
}

func gidVacancyCheck(client dynamodbiface.DynamoDBAPI, tblName string, gsiPosixIDIndex string,
	grpItem Item, isUpdate bool) (bool, error) {
	gidKeyConditionBuilder := expression.KeyAnd(
		expression.KeyEqual(expression.Key(DDBGsiPosixIDPK), expression.Value(grpItem.PosixId)),
		expression.KeyEqual(expression.Key(DDBGsiPosixIDSK), expression.Value(DDBRecordTypeGroupEnum)))
	proj := expression.NamesList(
		expression.Name(DDBGsiPosixIDPK),
		expression.Name(DDBGsiPosixIDSK),
		expression.Name(DDBRecordUUIDKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(gidKeyConditionBuilder).
		WithProjection(proj).
		Build()
	if exprErr != nil {
		log.Print("Failed to build DDB expression while checking for gid vacancy")
		return false, fmt.Errorf("Failed to build DDB expression while checking for gid vacancy")
	}
	gidVacancyQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(tblName),
		IndexName:                 aws.String(gsiPosixIDIndex),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}
	gidVacancyQueryResult, gidVacancyQueryErr := client.Query(gidVacancyQueryInput)
	if gidVacancyQueryErr != nil {
		log.Printf("Error querying gid vacancy for key condition %+v", gidKeyConditionBuilder)
		return false, fmt.Errorf("Error querying gid vacancy for key condition %+v", gidKeyConditionBuilder)
	}
	if len(gidVacancyQueryResult.Items) == 0 {
		log.Printf("Found no matching gid entries for key condition %+v", gidKeyConditionBuilder)
		return true, nil
	} else if len(gidVacancyQueryResult.Items) == 1 {
		log.Printf("Found one matching gid entry for key condition %+v", gidKeyConditionBuilder)
		gidItem := Item{}
		if err := dynamodbattribute.UnmarshalMap(gidVacancyQueryResult.Items[0], &gidItem); err != nil {
			log.Printf("Failed to unmarshall result into gid item for filter %+v", gidKeyConditionBuilder)
			return false, fmt.Errorf("Failed to unmarshall result into gid item for filter %+v", gidKeyConditionBuilder)
		}
		if gidItem.UUID == grpItem.UUID && isUpdate {
			//this means the request is to update the same existing group without modifying the GID
			log.Printf("group update requested but gid has not changed")
			return true, nil
		} else {
			//this means either that the request is to update an existing group or
			// that the request is to add a new group. But the GID is already taken.
			log.Printf("The requested GID %s is already taken up", grpItem.PosixId)
			return false, nil
		}
	}
	log.Printf("Found more than one matching gid entries for key condition %+v", gidKeyConditionBuilder)
	return false, fmt.Errorf("Found more than one matching gid entries for key condition %+v", gidKeyConditionBuilder)
}

func appendGroupPutTransactions(tblName string, grpItem Item, isUpdate bool, ddbTransactions []*dynamodb.TransactWriteItem) ([]*dynamodb.TransactWriteItem, error) {
	grpName := strings.TrimPrefix(grpItem.PK, DDBGroupRecordPKPrefix)
	putGrpItem, marshalErr := dynamodbattribute.MarshalMap(grpItem)
	if marshalErr != nil {
		log.Printf("Failed to marshal group item for user %s", grpName)
		return nil, fmt.Errorf("Failed to marshal group item for user %s", grpName)
	}
	grpPut := &dynamodb.Put{
		Item:      putGrpItem,
		TableName: aws.String(tblName),
	}
	if isUpdate {
		conditionExpression := fmt.Sprintf("attribute_exists(%s) and attribute_exists(%s)", DDBRecordPK, DDBRecordSK)
		grpPut.ConditionExpression = &conditionExpression
	} else {
		conditionExpression := fmt.Sprintf("attribute_not_exists(%s) and attribute_not_exists(%s)", DDBRecordPK, DDBRecordSK)
		grpPut.ConditionExpression = &conditionExpression
	}
	putGroupItemTransactWriteItem := &dynamodb.TransactWriteItem{
		Put: grpPut,
	}
	ddbTransactions = append(ddbTransactions, putGroupItemTransactWriteItem)

	return ddbTransactions, nil
}

func fetchGroupByPK(client dynamodbiface.DynamoDBAPI, tblName string, grpPrimaryKey map[string]string, grpItem *Item) error {
	pk, err := dynamodbattribute.MarshalMap(grpPrimaryKey)
	if err != nil {
		log.Printf("Failed to marshal primary key while fetching group for filter %+v", grpPrimaryKey)
		return fmt.Errorf("Failed to marshal primary key while fetching group for filter %+v", grpPrimaryKey)
	}
	proj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordNameKey),
		expression.Name(DDBRecordUUIDKey),
		expression.Name(DDBRecordCreatedKey),
		expression.Name(DDBRecordTypeKey),
		expression.Name(DDBRecordPosixIdKey),
	)
	expr, exprErr := expression.NewBuilder().WithProjection(proj).Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching group for filter %+v", grpPrimaryKey)
		return fmt.Errorf("Failed to build DDB expression while fetching group for filter %+v", grpPrimaryKey)
	}
	input := &dynamodb.GetItemInput{
		TableName:                aws.String(tblName),
		Key:                      pk,
		ExpressionAttributeNames: expr.Names(),
		ProjectionExpression:     expr.Projection(),
	}
	result, getItemErr := client.GetItem(input)
	if getItemErr != nil {
		log.Printf("Failed to get group for filter %+v from DDB", grpPrimaryKey)
		return fmt.Errorf("Failed to get group for filter %+v from DDB", grpPrimaryKey)
	}
	if result.Item != nil {
		if err := dynamodbattribute.UnmarshalMap(result.Item, grpItem); err != nil {
			log.Printf("Failed to unmarshall result into group for filter %+v from DDB", grpPrimaryKey)
			return fmt.Errorf("Failed to unmarshall result into group for filter %+v from DDB", grpPrimaryKey)
		}
	}
	return nil
}

func fetchGroupByGsi(client dynamodbiface.DynamoDBAPI, tblName string, indexName string, keyConditionBuilder expression.KeyConditionBuilder, grpItem *Item) error {

	proj := expression.NamesList(
		expression.Name(DDBRecordPK),
		expression.Name(DDBRecordSK),
		expression.Name(DDBRecordNameKey),
		expression.Name(DDBRecordUUIDKey),
		expression.Name(DDBRecordCreatedKey),
		expression.Name(DDBRecordTypeKey),
		expression.Name(DDBRecordPosixIdKey),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(keyConditionBuilder).
		WithProjection(proj).
		Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching groups for key condition %+v", keyConditionBuilder)
		return fmt.Errorf("Failed to build DDB expression while fetching groups for key condition %+v", keyConditionBuilder)
	}
	groupsQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(tblName),
		IndexName:                 aws.String(indexName),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}
	groupsQueryResult, groupsQueryErr := client.Query(groupsQueryInput)
	if groupsQueryErr != nil {
		log.Printf("Error querying groups for key condition %+v", keyConditionBuilder)
		return fmt.Errorf("Error querying groups for key condition %+v", keyConditionBuilder)
	}
	if len(groupsQueryResult.Items) > 1 {
		log.Printf("Found more than one matching group for key condition %+v", keyConditionBuilder)
		return fmt.Errorf("Found more than one matching group for key condition %+v", keyConditionBuilder)
	} else if len(groupsQueryResult.Items) == 0 {
		log.Printf("Found no matching group for key condition %+v", keyConditionBuilder)
		return nil
	}
	if err := dynamodbattribute.UnmarshalMap(groupsQueryResult.Items[0], grpItem); err != nil {
		log.Printf("Failed to unmarshall result into group for filter %+v", keyConditionBuilder)
		return fmt.Errorf("Failed to unmarshall result into group for filter %+v", keyConditionBuilder)
	}
	return nil
}

func updateGroupByPK(client dynamodbiface.DynamoDBAPI, tblName string, groupItem Item) error {
	updateGroupErr := putGroup(client, tblName, groupItem, true)
	if updateGroupErr != nil {
		log.Printf("Failed to update group %s - %+v", strings.TrimPrefix(groupItem.PK, DDBGroupRecordPKPrefix), updateGroupErr)
		return fmt.Errorf("Failed to update group %s", strings.TrimPrefix(groupItem.PK, DDBGroupRecordPKPrefix))
	}
	return nil
}

func updateGroupByUUID(client dynamodbiface.DynamoDBAPI, tblName string, gsiUUIDIndexName string, gsiSGIndexName string, groupItem Item) error {
	uuidItem := Item{}
	uuidKeyConditionBuilder := expression.KeyEqual(expression.Key(DDBGsiUUIDPK), expression.Value(groupItem.UUID))
	fetchGroupErr := fetchGroupByGsi(client, tblName, gsiUUIDIndexName, uuidKeyConditionBuilder, &uuidItem)
	if fetchGroupErr != nil {
		log.Printf("Error in locating group with UUID %s to update - %+v", groupItem.UUID, fetchGroupErr)
		return fmt.Errorf("Error in locating group with UUID %s to update", groupItem.UUID)
	}
	if uuidItem.PK == "" {
		log.Printf("Failed to locate a group with UUID %s to update", groupItem.UUID)
		return fmt.Errorf("Failed to locate a group with UUID %s to update", groupItem.UUID)
	}
	if groupItem.PK == "" {
		groupItem.PK = uuidItem.PK
		groupItem.SK = uuidItem.SK
		updateErr := updateGroupByPK(client, tblName, groupItem)
		if updateErr != nil {
			return fmt.Errorf("update group by PK returned error - %+v", updateErr)
		}
	} else {
		if groupItem.PK == uuidItem.PK {
			updateErr := updateGroupByPK(client, tblName, groupItem)
			if updateErr != nil {
				return fmt.Errorf("update group by PK returned error - %+v", updateErr)
			}
		} else {
			ddbTransactions, appendGroupPutTransactionsErr := appendGroupPutTransactions(tblName, groupItem, false, make([]*dynamodb.TransactWriteItem, 0))
			if appendGroupPutTransactionsErr != nil {
				log.Printf("Error occurred while appending transactions for updating group with UUID %s - %+v", groupItem.UUID, appendGroupPutTransactionsErr)
				return fmt.Errorf("Error occurred while appending transactions for updating group with UUID %s", groupItem.UUID)
			}
			deleteGroupName := strings.TrimPrefix(uuidItem.PK, DDBGroupRecordPKPrefix)
			ddbTransactions, appendGroupDelTransactionsErr := appendGroupDeleteTransactions(client, tblName, deleteGroupName, ddbTransactions)
			if appendGroupDelTransactionsErr != nil {
				log.Printf("Error occurred while appending transactions for deleting group %s - %+v", deleteGroupName, appendGroupDelTransactionsErr)
				return fmt.Errorf("Error occurred while appending transactions for deleting group %s", deleteGroupName)
			}
			groupUpdateTransactionInput := &dynamodb.TransactWriteItemsInput{
				TransactItems: ddbTransactions,
			}
			_, groupUpdateTransactionErr := client.TransactWriteItems(groupUpdateTransactionInput)
			if groupUpdateTransactionErr != nil {
				log.Printf("DynamoDB returned error while executing group update transactions for UUID %s - %+v", groupItem.UUID, groupUpdateTransactionErr)
				return fmt.Errorf("DynamoDB returned error while executing group update transactions for UUID %s", groupItem.UUID)
			}
		}
	}
	updateSGErr := updateSecondaryGroups(client, tblName, gsiSGIndexName, uuidItem, groupItem)
	if updateSGErr != nil {
		log.Printf("Failure while updating secondary group entries for modified group - %+v", updateSGErr)
		return fmt.Errorf("Failure while updating secondary group entries for modified group - %+v", updateSGErr)
	}
	return nil
}

func appendGroupDeleteTransactions(client dynamodbiface.DynamoDBAPI, tblName string, group string, ddbTransactions []*dynamodb.TransactWriteItem) ([]*dynamodb.TransactWriteItem, error) {
	deleteGroupRecordPrimaryKey := map[string]string{
		DDBRecordPK: DDBGroupRecordPKPrefix + group,
		DDBRecordSK: DDBGroupRecordSKPrefix + group,
	}
	deleteGroupMap, marshalErr := dynamodbattribute.MarshalMap(deleteGroupRecordPrimaryKey)
	if marshalErr != nil {
		log.Printf("Failed to marshal primary key of group %+v", deleteGroupRecordPrimaryKey)
		return nil, fmt.Errorf("Failed to marshal primary key of group %+v", deleteGroupRecordPrimaryKey)
	}
	groupDelete := &dynamodb.Delete{
		Key:       deleteGroupMap,
		TableName: aws.String(tblName),
	}
	deleteUserItemTransactWriteItem := &dynamodb.TransactWriteItem{
		Delete: groupDelete,
	}
	ddbTransactions = append(ddbTransactions, deleteUserItemTransactWriteItem)
	return ddbTransactions, nil
}

func deleteSecondaryGroups(client dynamodbiface.DynamoDBAPI, tblName string, gsiSGIndexName string, group string) (int, error) {
	secGroupUserItems, appendUsersForSecGroupErr := appendUsersForSecondaryGroup(client, tblName, gsiSGIndexName, group, []Item{})
	if appendUsersForSecGroupErr != nil {
		log.Printf("Failed to fetch users for secondary group %s - %+v", group, appendUsersForSecGroupErr)
		return 0, fmt.Errorf("Failed to fetch users for secondary group %s", group)
	}
	if len(secGroupUserItems) == 0 {
		return 0, nil
	}
	numberOfBatches := (len(secGroupUserItems) / 25)
	if len(secGroupUserItems)%25 > 0 {
		numberOfBatches++
	}
	batchWriteItems := make([]map[string][]*dynamodb.WriteRequest, numberOfBatches)
	for n, item := range secGroupUserItems {
		userSecondaryGroupRecordPrimaryKey := map[string]string{
			DDBRecordPK: item.PK,
			DDBRecordSK: item.SK,
		}
		primaryKey, err := dynamodbattribute.MarshalMap(userSecondaryGroupRecordPrimaryKey)
		if err != nil {
			log.Printf("Failed to marshal usersecgrouprecord %s,%s primary key attributes to delete", item.PK, item.SK)
			continue
		}
		deleteItemWriteRequest := &dynamodb.WriteRequest{
			DeleteRequest: &dynamodb.DeleteRequest{
				Key: primaryKey,
			},
		}
		if batchWriteItems[n/25] == nil {
			batchWriteItems[n/25] = map[string][]*dynamodb.WriteRequest{}
		}
		if batchWriteItems[n/25][tblName] == nil {
			batchWriteItems[n/25][tblName] = make([]*dynamodb.WriteRequest, 0)
		}
		batchWriteItems[n/25][tblName] = append(batchWriteItems[n/25][tblName], deleteItemWriteRequest)
	}
	for i, n := 0, len(batchWriteItems); i < len(batchWriteItems) && i <= (n*2)-1; i++ {
		input := &dynamodb.BatchWriteItemInput{
			RequestItems:                batchWriteItems[i],
			ReturnItemCollectionMetrics: aws.String("SIZE"),
		}
		output, err := client.BatchWriteItem(input)
		if err != nil {
			log.Printf("Errors encountered while deleting user secondary group records - %+v", err.Error())
		}
		if len(output.UnprocessedItems) > 0 {
			batchWriteItems = append(batchWriteItems, output.UnprocessedItems)
		}
	}
	return len(secGroupUserItems), nil
}

func updateSecondaryGroups(client dynamodbiface.DynamoDBAPI, tblName string, gsiSGIndexName string, oldGroupItem, newGroupItem Item) error {
	secGroupUserItems, appendUsersForSecGroupErr := appendUsersForSecondaryGroup(client, tblName, gsiSGIndexName, oldGroupItem.Name, []Item{})
	if appendUsersForSecGroupErr != nil {
		log.Printf("Failed to fetch users for secondary group %s - %+v", oldGroupItem.Name, appendUsersForSecGroupErr)
		return fmt.Errorf("Failed to fetch users for secondary group %s", oldGroupItem.Name)
	}
	numberOfBatches := (len(secGroupUserItems) / 25)
	if len(secGroupUserItems)%25 > 0 {
		numberOfBatches++
	}
	batchWriteDelItems := make([]map[string][]*dynamodb.WriteRequest, numberOfBatches)
	batchWritePutItems := make([]map[string][]*dynamodb.WriteRequest, numberOfBatches)
	for n, item := range secGroupUserItems {
		delUserSecGroupRecordPrimaryKey := map[string]string{
			DDBRecordPK: item.PK,
			DDBRecordSK: item.SK,
		}
		delPrimaryKey, err := dynamodbattribute.MarshalMap(delUserSecGroupRecordPrimaryKey)
		if err != nil {
			log.Printf("Failed to marshal usersecgrouprecord %s,%s primary key attributes to delete", item.PK, item.SK)
			continue
		}
		delItemWriteRequest := &dynamodb.WriteRequest{
			DeleteRequest: &dynamodb.DeleteRequest{
				Key: delPrimaryKey,
			},
		}
		if batchWriteDelItems[n/25] == nil {
			batchWriteDelItems[n/25] = map[string][]*dynamodb.WriteRequest{}
		}
		if batchWriteDelItems[n/25][tblName] == nil {
			batchWriteDelItems[n/25][tblName] = make([]*dynamodb.WriteRequest, 0)
		}
		batchWriteDelItems[n/25][tblName] = append(batchWriteDelItems[n/25][tblName], delItemWriteRequest)

		//here creating batch put requests
		userSecGroupItem := Item{
			PK:             item.PK,
			SK:             DDBUserSecondaryGroupRecordSKPrefix + newGroupItem.Name,
			PosixId:        newGroupItem.PosixId,
			SecondaryGroup: newGroupItem.Name,
		}
		putUserSecGroupItem, marshalErr := dynamodbattribute.MarshalMap(userSecGroupItem)
		if marshalErr != nil {
			log.Printf("Failed to marshal secondary group item with key %s - %s", item.PK, DDBUserSecondaryGroupRecordSKPrefix+newGroupItem.Name)
			return fmt.Errorf("Failed to marshal secondary group item with key %s - %s", item.PK, DDBUserSecondaryGroupRecordSKPrefix+newGroupItem.Name)
		}
		putItemWriteRequest := &dynamodb.WriteRequest{
			PutRequest: &dynamodb.PutRequest{
				Item: putUserSecGroupItem,
			},
		}
		if batchWritePutItems[n/25] == nil {
			batchWritePutItems[n/25] = map[string][]*dynamodb.WriteRequest{}
		}
		if batchWritePutItems[n/25][tblName] == nil {
			batchWritePutItems[n/25][tblName] = make([]*dynamodb.WriteRequest, 0)
		}
		batchWritePutItems[n/25][tblName] = append(batchWritePutItems[n/25][tblName], putItemWriteRequest)
	}
	for i, n := 0, len(batchWriteDelItems); i < len(batchWriteDelItems) && i <= (n*2)-1; i++ {
		input := &dynamodb.BatchWriteItemInput{
			RequestItems: batchWriteDelItems[i],
		}
		output, err := client.BatchWriteItem(input)
		if err != nil {
			log.Printf("Errors encountered while deleting user secondary group records - %+v", err.Error())
		}
		if len(output.UnprocessedItems) > 0 {
			batchWriteDelItems = append(batchWriteDelItems, output.UnprocessedItems)
		}
	}

	for i, n := 0, len(batchWritePutItems); i < len(batchWritePutItems) && i <= (n*2)-1; i++ {
		input := &dynamodb.BatchWriteItemInput{
			RequestItems: batchWritePutItems[i],
		}
		output, err := client.BatchWriteItem(input)
		if err != nil {
			log.Printf("Errors encountered while adding user secondary group records - %+v", err.Error())
		}
		if len(output.UnprocessedItems) > 0 {
			batchWritePutItems = append(batchWritePutItems, output.UnprocessedItems)
		}
	}
	return nil
}

func appendUsersForSecondaryGroup(client dynamodbiface.DynamoDBAPI, tblName string, gsiSGIndexName string, group string, secGroupUserItems []Item) ([]Item, error) {
	secGroupUsersCond := expression.KeyAnd(
		expression.Key(DDBGsiSecondaryGroupPK).Equal(expression.Value(group)),
		expression.Key(DDBGsiSecondaryGroupSK).BeginsWith(DDBUserRecordPKPrefix),
	)
	secGroupUsersProj := expression.NamesList(
		expression.Name(DDBGsiSecondaryGroupSK),
		expression.Name(DDBRecordSK),
	)
	expr, exprErr := expression.NewBuilder().
		WithKeyCondition(secGroupUsersCond).
		WithProjection(secGroupUsersProj).
		Build()
	if exprErr != nil {
		log.Printf("Failed to build DDB expression while fetching users for sec group %s", group)
		return nil, fmt.Errorf("Failed to build DDB expression while fetching users for sec group %s", group)
	}
	secGroupUsersQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(tblName),
		IndexName:                 aws.String(gsiSGIndexName),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}
	secGroupUsersQueryResult, secGroupUsersQueryErr := client.Query(secGroupUsersQueryInput)
	if secGroupUsersQueryErr != nil {
		log.Printf("Error querying users for security group %s - %+v", group, secGroupUsersQueryErr)
		return nil, fmt.Errorf("Error querying users for security group %s", group)
	}
	secGroups := []Item{}
	if len(secGroupUsersQueryResult.Items) > 0 {
		if err := dynamodbattribute.UnmarshalListOfMaps(secGroupUsersQueryResult.Items, &secGroups); err != nil {
			log.Printf("Failed to unmarshall secondary group users results for group %s - %+v", group, err)
			return nil, fmt.Errorf("Failed to unmarshall secondary group users results for group %s", group)
		}
		secGroupUserItems = append(secGroupUserItems, secGroups...)
	}
	return secGroupUserItems, nil
}

func (c *DefaultDynamoDBStoreGroup) UnmarshalJSON(b []byte) error {
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
		c.GroupUniqueIdentifier = &uuid
	} else {
		log.Print("uuid field is not present in the JSON")
	}

	a := c.DefaultPosixGroup
	if x, found := generic["name"]; found {
		var name string
		var ok bool
		if name, ok = x.(string); !ok {
			log.Printf("name field in JSON is not a valid string - %+v", x)
			return fmt.Errorf("name field in JSON is not a valid string")
		}
		a.SetGroupsName(&name)
	} else {
		log.Print("name field is not present in the JSON")
	}

	if x, found := generic["gid"]; found {
		if gid, ok := x.(float64); !ok {
			log.Printf("gid parameter is not passed as a JSON number")
			var gidS string
			if gidS, ok = x.(string); !ok {
				log.Printf("gid field in JSON is not passed as string either - %+v", x)
				return fmt.Errorf("gid field in JSON is not passed as string or int")
			}
			gid, err := strconv.Atoi(gidS)
			if err != nil {
				log.Printf("gid field value could not be cast to integer - %+v", x)
				return fmt.Errorf("gid field value could not be cast to integer")
			}
			gid16 := uint16(gid)
			a.SetGroupID(&gid16)
		} else {
			gid16 := uint16(gid)
			a.SetGroupID(&gid16)
		}
	} else {
		log.Print("gid field is not present in the JSON")
	}

	return nil
}

func (a DefaultDynamoDBStoreGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		GroupUniqueIdentifier string `json:"uuid,omitempty"`
		Gid                   uint16 `json:"gid,omitempty"`
		Name                  string `json:"name,omitempty"`
	}{
		GroupUniqueIdentifier: *a.GroupUniqueIdentifier,
		Gid:                   *a.GetGroupID(),
		Name:                  *a.GetGroupName(),
	})
}
