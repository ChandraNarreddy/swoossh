package storage

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/user"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"golang.org/x/crypto/ssh"
)

var grpSearchOutputItems = []map[string]*dynamodb.AttributeValue{
	{
		DDBRecordPK:         &dynamodb.AttributeValue{S: strPtr("group#1")},
		DDBRecordSK:         &dynamodb.AttributeValue{S: strPtr("group#1")},
		DDBRecordNameKey:    &dynamodb.AttributeValue{S: strPtr("one")},
		DDBRecordUUIDKey:    &dynamodb.AttributeValue{S: strPtr("g1")},
		DDBRecordTypeKey:    &dynamodb.AttributeValue{S: strPtr("group")},
		DDBRecordPosixIdKey: &dynamodb.AttributeValue{S: strPtr("1")},
	},
	{
		DDBRecordPK:         &dynamodb.AttributeValue{S: strPtr("group#2")},
		DDBRecordSK:         &dynamodb.AttributeValue{S: strPtr("group#2")},
		DDBRecordNameKey:    &dynamodb.AttributeValue{S: strPtr("two")},
		DDBRecordUUIDKey:    &dynamodb.AttributeValue{S: strPtr("g2")},
		DDBRecordTypeKey:    &dynamodb.AttributeValue{S: strPtr("group")},
		DDBRecordPosixIdKey: &dynamodb.AttributeValue{S: strPtr("2")},
	},
	{
		DDBRecordPK:         &dynamodb.AttributeValue{S: strPtr("group#3")},
		DDBRecordSK:         &dynamodb.AttributeValue{S: strPtr("group#3")},
		DDBRecordNameKey:    &dynamodb.AttributeValue{S: strPtr("three")},
		DDBRecordUUIDKey:    &dynamodb.AttributeValue{S: strPtr("g3")},
		DDBRecordTypeKey:    &dynamodb.AttributeValue{S: strPtr("group")},
		DDBRecordPosixIdKey: &dynamodb.AttributeValue{S: strPtr("3")},
	},
}

func TestDefaultDynamoDBStoreSearchGroups(t *testing.T) {
	var temp interface{}
	if _, err := DefaultDynamoDBStoreSearchGroups(temp, &DefaultDynamoDBStore{}); err == nil {
		t.Error("GroupSearchfilter check failed")
	}
	nilNameSearchFilter := &DefaultStoreGroupSearchFilter{}
	if _, err := DefaultDynamoDBStoreSearchGroups(nilNameSearchFilter, &DefaultDynamoDBStore{}); err == nil {
		t.Error("Nil GroupSearchfilter check failed")
	}
	queryOutput = dynamodb.QueryOutput{
		Items:            grpSearchOutputItems,
		LastEvaluatedKey: grpSearchOutputItems[2],
	}
	mockClient := &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	filter := &DefaultStoreGroupSearchFilter{
		GroupNameSearchProjection: strPtr(""),
		PageToken:                 strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                  intPtr(3),
		Order:                     &forw,
	}
	resp, err := DefaultDynamoDBStoreSearchGroups(filter, ddbStore)
	if err != nil {
		t.Errorf("DefaultDynamoDBStoreSearchGroups returned error - %+v", err.Error())
	}
	if len(resp.GetGroupSearchResults()) != len(grpSearchOutputItems) {
		t.Error("GetGroupSearchResults length does not match with supplied output items")
	}
	if _, ok := resp.(*DefaultStoreGroupSearchResponse); !ok {
		t.Error("DefaultDynamoDBStoreSearchGroups is not returning DefaultStoreUserSearchResponse")
	}

	queryOutput = dynamodb.QueryOutput{
		Items:            []map[string]*dynamodb.AttributeValue{},
		LastEvaluatedKey: nil,
	}
	mockClient = &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	filter = &DefaultStoreGroupSearchFilter{
		GroupNameSearchProjection: strPtr(""),
		PageToken:                 strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                  intPtr(3),
		Order:                     &forw,
	}
	resp, err = DefaultDynamoDBStoreSearchGroups(filter, ddbStore)
	if err != nil {
		t.Errorf("DefaultDynamoDBStoreSearchGroups returned error - %+v", err.Error())
	}
	if len(resp.GetGroupSearchResults()) != 0 {
		t.Error("GetGroupSearchResults length is not zero for zero results")
	}

	queryOutput = dynamodb.QueryOutput{
		Items:            grpSearchOutputItems,
		LastEvaluatedKey: grpSearchOutputItems[2],
	}
	mockClient = &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	noOrderfilter := &DefaultStoreGroupSearchFilter{
		GroupNameSearchProjection: strPtr(""),
		PageToken:                 strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                  intPtr(3),
	}
	resp, err = DefaultDynamoDBStoreSearchGroups(noOrderfilter, ddbStore)
	if err != nil {
		t.Errorf("DefaultDynamoDBStoreSearchUsers returned error - %+v", err.Error())
	}

	queryOutput = dynamodb.QueryOutput{
		Items:            grpSearchOutputItems,
		LastEvaluatedKey: grpSearchOutputItems[2],
	}
	mockClient = &mockStoreDynamoDBClient{}
	ddbStore.DDBClient = mockClient
	revOrderfilter := &DefaultStoreGroupSearchFilter{
		GroupNameSearchProjection: strPtr(""),
		PageToken:                 strPtr("D_-HBAEC_4gAAQwB_4IAAFb_gQMBAv-CAAEKAQFCAQoAAQRCT09MAQIAAQJCUwH_hAABAUwB_4YAAQFNAf-IAAEBTgEMAAECTlMB_4oAAQROVUxMAQIAAQFTAQwAAQJTUwH_igAAABf_gwIBAQlbXVtddWludDgB_4QAAQoAACn_hQIBARpbXSpkeW5hbW9kYi5BdHRyaWJ1dGVWYWx1ZQH_hgAB_4IAABf_iQIBAQlbXSpzdHJpbmcB_4oAAQwAAEb_iAADAnNrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcABHR5cGUJBHVzZXIAAnBrCRV1c2VyI2NoYW5kcmEuYmxvZ2dpbmcA"),
		PageSize:                  intPtr(6),
		Order:                     &rev,
	}
	resp, err = DefaultDynamoDBStoreSearchGroups(revOrderfilter, ddbStore)
	if err != nil {
		t.Errorf("GetUserSearchResults returned error - %+v", err.Error())
	}
}

func TestDefaultDynamoDBStoreCreateGroup(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client
	grp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g1"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(345),
			Name: strPtr("Grp1"),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(grp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}

	notDefaultDynamoDBStoreGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(567),
		Name: strPtr("Grp2"),
	}
	if e := DefaultDynamoDBStoreCreateGroup(notDefaultDynamoDBStoreGrp, ddbStore); e == nil {
		t.Error("Error not raised when non-DefaultDynamoDBStoreGrp is passed")
	}

	nilNameGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g8"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid: uint16Ptr(989),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(nilNameGrp, ddbStore); e == nil {
		t.Error("Error not raised when nil name group is passed")
	}

	nilGIDUser := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g9"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Name: strPtr("Grp3"),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(nilGIDUser, ddbStore); e == nil {
		t.Error("Error not raised when nil gid group is passed")
	}

	usedGIDGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g10"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(345),
			Name: strPtr("Grp1"),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(usedGIDGrp, ddbStore); e == nil {
		t.Error("Error not raised when used up GID group is passed")
	}

	usedNameGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g9"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(345),
			Name: strPtr("Grp10"),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(usedNameGrp, ddbStore); e == nil {
		t.Error("Error not raised when used name group is passed")
	}
}

func TestDefaultDynamoDBStoreGetGroup(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client
	grp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g1"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(345),
			Name: strPtr("Grp1"),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(grp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}

	fetchGrpFilters := []*DefaultStoreGroupFilter{
		&DefaultStoreGroupFilter{
			GroupNameProjection: strPtr("Grp1"),
			GroupIDProjection:   strPtr("345"),
		},
		&DefaultStoreGroupFilter{
			GroupIDProjection: strPtr("345"),
		},
		&DefaultStoreGroupFilter{
			GroupUniqueIdentifierProjection: strPtr(""),
		},
	}

	for _, filter := range fetchGrpFilters {
		result, e := DefaultDynamoDBStoreGetGroup(filter, ddbStore)
		if e != nil {
			t.Errorf("Get Group returned error %+v for filter %+v", e.Error(), filter)
		}
		if result == nil {
			t.Errorf("Get Group did not return any result for filter %+v", filter)
		}
		defaultDynamoDBStoreGrp, ok := result.(DefaultDynamoDBStoreGroup)
		if !ok {
			t.Errorf("Get User returned a non DefaultDynamoDBStoreGroup type")
		} else {
			if *defaultDynamoDBStoreGrp.Gid != *grp.Gid ||
				*defaultDynamoDBStoreGrp.Name != *grp.Name {
				t.Errorf("Get Group returned user does not match up to created Group for filter - %+v", filter)
			}
		}
		uuid := *defaultDynamoDBStoreGrp.GroupUniqueIdentifier
		fetchGrpFilters[2].GroupUniqueIdentifierProjection = &uuid
	}

	nonDefaultStoreGrpFilter := struct{ GroupUniqueIdentifierProjection *string }{
		GroupUniqueIdentifierProjection: strPtr("uuid"),
	}
	if _, e := DefaultDynamoDBStoreGetGroup(nonDefaultStoreGrpFilter, ddbStore); e == nil {
		t.Errorf("Get Group did not err when nonDefaultStoreGroupFilter is passed")
	}
}

func TestDefaultDynamoDBStoreUpdateGroup(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client

	grp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g1"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(345),
			Name: strPtr("Grp1"),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(grp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}

	filter := &DefaultStoreGroupFilter{
		GroupNameProjection: strPtr("Grp1"),
		GroupIDProjection:   strPtr("345"),
	}
	result, e := DefaultDynamoDBStoreGetGroup(filter, ddbStore)
	if e != nil {
		t.Errorf("Get Group returned error %+v for filter %+v", e.Error(), filter)
	}
	if result == nil {
		t.Errorf("Get Group did not return any result for filter %+v", filter)
	}
	existingGrp, ok := result.(DefaultDynamoDBStoreGroup)
	if !ok {
		t.Errorf("Get Group returned a non DefaultDynamoDBStoreGroup type")
	}

	modGrp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: existingGrp.GroupUniqueIdentifier,
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(897),
			Name: strPtr("Grp2"),
		},
	}
	e = DefaultDynamoDBStoreUpdateGroup(modGrp, ddbStore)
	if e != nil {
		t.Errorf("Update Group returned error - %+v", e.Error())
	} else {
		filter := &DefaultStoreGroupFilter{
			GroupUniqueIdentifierProjection: existingGrp.GroupUniqueIdentifier,
		}
		result, e := DefaultDynamoDBStoreGetGroup(filter, ddbStore)
		if e != nil {
			t.Errorf("Get Group returned error %+v for filter %+v", e.Error(), filter)
		}
		if result == nil {
			t.Errorf("Get Group did not return any result for filter %+v", filter)
		}
		modifiedGrp, ok := result.(DefaultDynamoDBStoreGroup)
		if !ok {
			t.Errorf("Get group returned a non DefaultDynamoDBStoreGroup type")
		}
		if *modGrp.Gid != *modifiedGrp.Gid ||
			*modGrp.Name != *modifiedGrp.Name {
			t.Error("Updated group does not match up to modifications sought")
		}
	}

	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	secGrps := []group.PosixGroup{
		modGrp,
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
	if e := DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}

	modGrp2 := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: existingGrp.GroupUniqueIdentifier,
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(123),
			Name: strPtr("Grp2"),
		},
	}
	e = DefaultDynamoDBStoreUpdateGroup(modGrp2, ddbStore)
	if e != nil {
		t.Errorf("Update Group returned error - %+v", e.Error())
	} else {
		filter := &DefaultStoreGroupFilter{
			GroupUniqueIdentifierProjection: existingGrp.GroupUniqueIdentifier,
		}
		result, e := DefaultDynamoDBStoreGetGroup(filter, ddbStore)
		if e != nil {
			t.Errorf("Get Group returned error %+v for filter %+v", e.Error(), filter)
		}
		if result == nil {
			t.Errorf("Get Group did not return any result for filter %+v", filter)
		}
		modifiedGrp, ok := result.(DefaultDynamoDBStoreGroup)
		if !ok {
			t.Errorf("Get group returned a non DefaultDynamoDBStoreGroup type")
		}
		if *modGrp2.Gid != *modifiedGrp.Gid ||
			*modGrp2.Name != *modifiedGrp.Name {
			t.Error("Updated group does not match up to modifications sought")
		}
	}
}

func TestDefaultDynamoDBStoreDeleteGroup(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client

	grp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("g1"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(345),
			Name: strPtr("Grp1"),
		},
	}
	if e := DefaultDynamoDBStoreCreateGroup(grp, ddbStore); e != nil {
		t.Errorf("Create secondary group returned error %+v", e.Error())
	}

	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k="))
	primGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(123),
		Name: strPtr("pname"),
	}
	secGrp := &group.DefaultPosixGroup{
		Gid:  uint16Ptr(345),
		Name: strPtr("Grp1"),
	}
	secGrps := []group.PosixGroup{
		secGrp,
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
	if e := DefaultDynamoDBStoreCreateUser(usr, ddbStore); e != nil {
		t.Errorf("Create user returned error %+v", e.Error())
	}

	filter := &DefaultStoreGroupFilter{
		GroupNameProjection: strPtr("Grp1"),
		GroupIDProjection:   strPtr("345"),
	}
	result, e := DefaultDynamoDBStoreGetGroup(filter, ddbStore)
	if e != nil {
		t.Errorf("Get Group returned error %+v for filter %+v", e.Error(), filter)
	}
	if result == nil {
		t.Errorf("Get Group did not return any result for filter %+v", filter)
	}

	deleteGrp := &group.DefaultPosixGroup{
		Name: strPtr("Grp1"),
	}
	e = DefaultDynamoDBStoreDeleteGroup(deleteGrp, ddbStore)
	if e != nil {
		t.Errorf("Delete group returned error for valid delete request - %+v", e.Error())
	}
	result, e = DefaultDynamoDBStoreGetGroup(filter, ddbStore)
	if e != nil {
		t.Errorf("Get group did not return nil error for filter")
	}
	if result != nil {
		t.Error("Get group did not return nil result after deletion")
	}

	e = DefaultDynamoDBStoreDeleteGroup(deleteGrp, ddbStore)
	if e == nil {
		t.Errorf("Delete group did not return error for already deleted group")
	}

	items, er := appendUsersForSecondaryGroup(ddbStore.DDBClient, *ddbStore.TableName, *ddbStore.GSISecondaryGroupIndexName, "Grp1", []Item{})
	if er != nil {
		t.Errorf("append users for deleted secondary groups errored out - %+v", er)
	}
	if len(items) != 0 {
		t.Errorf("Length of users for deleted secondary group is not zero")
	}

	//attempting to delete unexisting group
	nonexistingGrp := &group.DefaultPosixGroup{
		Name: strPtr("Non-existing-123"),
	}
	e = DefaultDynamoDBStoreDeleteGroup(nonexistingGrp, ddbStore)
	if e == nil {
		t.Errorf("Delete group returned nil error for non-existant group")
	}
}

func TestDefaultDynamoDBStoreGroupUnmarshalJSON(t *testing.T) {
	rawGrp := json.RawMessage(`{
      "uuid": "3ba9bc23-9f2d-4af6-955c-861f72b1014e",
      "gid": "23",
      "name": "block"
      }`)
	bytes, err := json.Marshal(&rawGrp)
	if err != nil {
		panic(err)
	}
	grp := &DefaultDynamoDBStoreGroup{
		DefaultPosixGroup: &group.DefaultPosixGroup{},
	}
	e := grp.UnmarshalJSON(bytes)
	if e != nil {
		t.Errorf("Failed to unmarshal group json %+v", e.Error())
	}

	validateGrp := &DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("3ba9bc23-9f2d-4af6-955c-861f72b1014e"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(23),
			Name: strPtr("block"),
		},
	}
	if !reflect.DeepEqual(validateGrp, grp) {
		t.Error("Marshaled group is not matching up to sent group")
	}

}

func TestDefaultDynamoDBStoreGroupMarshalJSON(t *testing.T) {
	grp := DefaultDynamoDBStoreGroup{
		GroupUniqueIdentifier: strPtr("3ba9bc23-9f2d-4af6-955c-861f72b1014e"),
		DefaultPosixGroup: &group.DefaultPosixGroup{
			Gid:  uint16Ptr(2321),
			Name: strPtr("block"),
		},
	}
	grpBytes, e := grp.MarshalJSON()
	if e != nil {
		t.Errorf("Marshaljson returned error %+v", e.Error())
	}
	rawGrp := json.RawMessage(`{
      "uuid": "3ba9bc23-9f2d-4af6-955c-861f72b1014e",
      "gid": 2321,
      "name": "block"
      }`)
	rawBytes, err := json.Marshal(&rawGrp)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(grpBytes, rawBytes) {
		t.Errorf("Marshaljson of group is not the same as raw json")
	}
}
