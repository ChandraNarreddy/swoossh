package authorizedprincipals

import (
	"errors"
	"fmt"
	"os/exec"
	osuser "os/user"
	"testing"
	"time"

	group "github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/sshcert"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

func ptrUint16(p uint16) *uint16 {
	return &p
}

func ptrUint32(p uint32) *uint32 {
	return &p
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

type testUsrGrpLookUp struct {
	userLookupErr     error
	userLookupResult  *osuser.User
	gidLookupErr      error
	gidLookupResult   *osuser.Group
	groupLookupErr    error
	groupLookupResult *osuser.Group
}

func (c *testUsrGrpLookUp) Lookup(username string) (*osuser.User, error) {
	return c.userLookupResult, c.userLookupErr
}
func (c *testUsrGrpLookUp) LookupGroupId(gid string) (*osuser.Group, error) {
	return c.gidLookupResult, c.gidLookupErr
}
func (c *testUsrGrpLookUp) LookupGroup(name string) (*osuser.Group, error) {
	return c.groupLookupResult, c.groupLookupErr
}

type testPosixCert struct {
	principal *string
	uid       *uint32
	primGrp   *group.DefaultPosixGroup
}

func (c *testPosixCert) GetPrincipalName() (string, error) {
	p := c.principal
	if p == nil {
		return "", fmt.Errorf("principal is nil")
	}
	return *p, nil
}
func (c *testPosixCert) SetPrincipalName(p string) error {
	if p == "return error" {
		c.principal = nil
		return fmt.Errorf("Some error")
	}
	c.principal = &p
	return nil
}
func (c *testPosixCert) GetUIDClaim() (uint32, error) {
	p := c.uid
	if p == nil {
		return 0, fmt.Errorf("uid is nil")
	}
	return *p, nil
}
func (c *testPosixCert) SetUIDClaim(p uint32) error {
	if p == 9999 {
		c.uid = nil
		return fmt.Errorf("Some error")
	}
	c.uid = &p
	return nil
}
func (c *testPosixCert) GetPrimaryGroupClaim() (group.PosixGroup, error) {
	if c.primGrp == nil {
		return nil, fmt.Errorf("primary group is nil")
	}
	return c.primGrp, nil
}
func (c *testPosixCert) SetPrimaryGroupClaim(p group.PosixGroup) error {
	if p == nil {
		c.primGrp = nil
		return fmt.Errorf("Some error")
	}
	c.primGrp = p.(*group.DefaultPosixGroup)
	return nil
}

type testLatestPasswdHashCert struct {
	testPosixCert
	passwdHash       string
	passwdHashGetErr error
}

func (c *testLatestPasswdHashCert) GetLatestPasswdHash() (string, error) {
	return c.passwdHash, c.passwdHashGetErr
}
func (c *testLatestPasswdHashCert) SetLatestPasswdHash(string) error {
	return nil
}

type testBaseHost struct {
	buf        string
	targetUser string
}

func (c *testBaseHost) PrintAuthorizedPrincipalsFile(user string, cert sshcert.Cert) error {
	c.buf = fmt.Sprintf("%s", user)
	return nil
}

func (c *testBaseHost) GetSSHCmdTargetUser() string {
	return c.targetUser
}

type testPosixHostResetPasswd struct {
	testBaseHost
	resetPasswdErr error
}

func (c *testPosixHostResetPasswd) PosixHostResetPasswd(user string, passwdHash string) error {
	return c.resetPasswdErr
}

func TestDefaultPosixHostMatchCertClaimToAnExistingAccount(t *testing.T) {
	//DefaultPosixHostMatchCertClaimToAnExistingAccount(cert sshcert.CertPosixAccount, host PosixHost, resetPasswdWithLatestFromCert bool) (bool, string, error)
	errPrincipalPosixCert := &testPosixCert{
		uid:     ptrUint32(123),
		primGrp: &group.DefaultPosixGroup{},
	}
	_, _, err := DefaultPosixHostMatchCertClaimToAnExistingAccount(errPrincipalPosixCert, &testBaseHost{}, false, &testUsrGrpLookUp{})
	if err == nil {
		t.Errorf("MatchCertClaimToAnExistingAccount did not raise error for errored out principal name from cert")
	}
	errUidPosixCert := &testPosixCert{
		principal: strPtr(""),
		primGrp:   &group.DefaultPosixGroup{},
	}
	_, _, err = DefaultPosixHostMatchCertClaimToAnExistingAccount(errUidPosixCert, &testBaseHost{}, false, &testUsrGrpLookUp{})
	if err == nil {
		t.Errorf("MatchCertClaimToAnExistingAccount did not raise error for errored out uid from cert")
	}

	validPosixCert := &testPosixCert{
		principal: strPtr("valid_user"),
		uid:       ptrUint32(123),
		primGrp:   &group.DefaultPosixGroup{},
	}
	validOSUserLookup := &testUsrGrpLookUp{
		userLookupResult: &osuser.User{
			Uid:      "123",
			Username: "valid_user",
		},
	}
	valid, user, matchErr := DefaultPosixHostMatchCertClaimToAnExistingAccount(validPosixCert, &testBaseHost{}, false, validOSUserLookup)
	if matchErr != nil {
		t.Errorf("MatchCertClaimToAnExistingAccount errored out for valid cert and posixhost combination")
	}
	if !valid {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected result for valid cert and posixhost combination")
	}
	if user != "valid_user" {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected principal value valid cert and posixhost combination")
	}

	mismatchOSUserLookup := &testUsrGrpLookUp{
		userLookupResult: &osuser.User{
			Uid:      "123",
			Username: "invalid_user",
		},
		userLookupErr: errors.New(""),
	}
	valid, user, matchErr = DefaultPosixHostMatchCertClaimToAnExistingAccount(validPosixCert, &testBaseHost{}, false, mismatchOSUserLookup)
	if matchErr != nil {
		t.Errorf("MatchCertClaimToAnExistingAccount errored out for valid yet mismatched cert and posixhost combination")
	}
	if valid {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected result for valid yet mismatched cert and posixhost combination")
	}
	if user != "" {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected principal value for valid yet mismatched cert and posixhost combination")
	}

	mismatchOSUIDLookup := &testUsrGrpLookUp{
		userLookupResult: &osuser.User{
			Uid:      "345",
			Username: "valid_user",
		},
	}
	valid, user, matchErr = DefaultPosixHostMatchCertClaimToAnExistingAccount(validPosixCert, &testBaseHost{}, false, mismatchOSUIDLookup)
	if matchErr != nil {
		t.Errorf("MatchCertClaimToAnExistingAccount errored out for valid yet mismatched cert and posixhost combination")
	}
	if valid {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected result for valid yet mismatched cert and posixhost combination")
	}
	if user != "" {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected principal value for valid yet mismatched cert and posixhost combination")
	}

	resetPasswdHost := &testPosixHostResetPasswd{
		testBaseHost:   testBaseHost{},
		resetPasswdErr: nil,
	}
	latestPasswdCert := &testLatestPasswdHashCert{
		testPosixCert: testPosixCert{
			principal: strPtr("valid_user"),
			uid:       ptrUint32(123),
			primGrp:   &group.DefaultPosixGroup{},
		},
		passwdHash:       "$1",
		passwdHashGetErr: nil,
	}
	matchedOSUserLookup := &testUsrGrpLookUp{
		userLookupResult: &osuser.User{
			Uid:      "123",
			Username: "valid_user",
		},
	}
	valid, user, matchErr = DefaultPosixHostMatchCertClaimToAnExistingAccount(latestPasswdCert, resetPasswdHost, true, matchedOSUserLookup)
	if matchErr != nil {
		t.Errorf("MatchCertClaimToAnExistingAccount errored out for valid latestPasswdCert, resetPasswdHost and matchedOSUserLookup combination")
	}
	if !valid {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected result for valid latestPasswdCert, resetPasswdHost and matchedOSUserLookup combination")
	}
	if user != "valid_user" {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected principal value for valid latestPasswdCert, resetPasswdHost and matchedOSUserLookup combination")
	}

	valid, user, matchErr = DefaultPosixHostMatchCertClaimToAnExistingAccount(latestPasswdCert, &testBaseHost{}, true, matchedOSUserLookup)
	if matchErr == nil {
		t.Errorf("MatchCertClaimToAnExistingAccount did not throw error for unimplemented resetPasswdHost for valid latestPasswdCert and matchedOSUserLookup combination")
	}
	if valid {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected result for unimplemented resetPasswdHost for valid latestPasswdCert and matchedOSUserLookup combination")
	}
	if user == "valid_user" {
		t.Errorf("MatchCertClaimToAnExistingAccount did not return expected principal value for unimplemented resetPasswdHost for valid latestPasswdCert and matchedOSUserLookup combination")
	}

	erroredOutLatestPasswdCert := &testLatestPasswdHashCert{
		testPosixCert: testPosixCert{
			principal: strPtr("valid_user"),
			uid:       ptrUint32(123),
			primGrp:   &group.DefaultPosixGroup{},
		},
		passwdHash:       "$1",
		passwdHashGetErr: errors.New(""),
	}
	_, _, matchErr = DefaultPosixHostMatchCertClaimToAnExistingAccount(erroredOutLatestPasswdCert, &testBaseHost{}, true, matchedOSUserLookup)
	if matchErr == nil {
		t.Errorf("MatchCertClaimToAnExistingAccount did not throw error for erroring out latestPasswdHashCert")
	}

	erroredOutResetPasswdHost := &testPosixHostResetPasswd{
		testBaseHost:   testBaseHost{},
		resetPasswdErr: errors.New(""),
	}
	_, _, matchErr = DefaultPosixHostMatchCertClaimToAnExistingAccount(latestPasswdCert, erroredOutResetPasswdHost, true, matchedOSUserLookup)
	if matchErr == nil {
		t.Errorf("MatchCertClaimToAnExistingAccount did not throw error for erroring out resetPasswdHost")
	}
}

type testPosixHostOSExec struct {
	testBaseHost
	osExecErr error
}

func (c *testPosixHostOSExec) PosixHostOSExec(stdInput []byte, cmdAndArgs ...string) (string, error) {
	return "", c.osExecErr
}

type testCreateGroupOSExecHost struct {
	testPosixHostOSExec
	createGrpErr error
}

func (c *testCreateGroupOSExecHost) PosixHostCreateGroupIfNotExists(group.PosixGroup) error {
	return c.createGrpErr
}

type testUserAuthorizeCreateGrpOSExecHost struct {
	testCreateGroupOSExecHost
	authorized   bool
	authorizeErr error
}

type testCreateGroupHost struct {
	testBaseHost
	createGrpErr error
}

func (c *testCreateGroupHost) PosixHostCreateGroupIfNotExists(group.PosixGroup) error {
	return c.createGrpErr
}

func (c *testUserAuthorizeCreateGrpOSExecHost) PosixHostUserAuthorize(user string, cert sshcert.CertPosixAccount) (bool, error) {
	return c.authorized, c.authorizeErr
}

func TestDefaultPosixHostAddUserToSystem(t *testing.T) {
	//DefaultPosixHostAddUserToSystem(userLogin string, cert sshcert.CertPosixAccount,
	///	host PosixHost, disableNewAccountAuthorization bool, userAddCmdOptions *DefaultPosixAddUserOptions) error
	validPosixCert := &testPosixCert{
		principal: strPtr("valid_user"),
		uid:       ptrUint32(123),
		primGrp: &group.DefaultPosixGroup{
			Gid:  ptrUint16(123),
			Name: strPtr("grp1"),
		},
	}
	addUserOptions := &DefaultPosixAddUserOptions{
		CreateHome:    true,
		BaseHomeDir:   "/home",
		ExpireDate:    ptrTime(time.Now().Add(2 * time.Hour)),
		LoginShell:    "/bin/sh",
		SystemAccount: false,
	}

	h1 := &testCreateGroupOSExecHost{
		testPosixHostOSExec: testPosixHostOSExec{
			testBaseHost: testBaseHost{},
			osExecErr:    nil,
		},
		createGrpErr: nil,
	}
	e1 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, h1, false, addUserOptions)
	if e1 == nil {
		t.Errorf("Add User to Sytem did not return error for valid host but unimplemented user authorize host")
	}

	h2 := &testUserAuthorizeCreateGrpOSExecHost{
		testCreateGroupOSExecHost: testCreateGroupOSExecHost{
			testPosixHostOSExec: testPosixHostOSExec{
				testBaseHost: testBaseHost{},
				osExecErr:    nil,
			},
			createGrpErr: nil,
		},
		authorized:   true,
		authorizeErr: errors.New(""),
	}
	e2 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, h2, false, addUserOptions)
	if e2 == nil {
		t.Errorf("Add User to Sytem did not return error for valid host but errored out user authorize host")
	}

	h3 := &testUserAuthorizeCreateGrpOSExecHost{
		testCreateGroupOSExecHost: testCreateGroupOSExecHost{
			testPosixHostOSExec: testPosixHostOSExec{
				testBaseHost: testBaseHost{},
				osExecErr:    nil,
			},
			createGrpErr: nil,
		},
		authorized:   false,
		authorizeErr: nil,
	}
	e3 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, h3, false, addUserOptions)
	if e3 == nil {
		t.Errorf("Add User to Sytem did not return error for valid host but false result from user authorize host")
	}

	h4 := &testUserAuthorizeCreateGrpOSExecHost{
		testCreateGroupOSExecHost: testCreateGroupOSExecHost{
			testPosixHostOSExec: testPosixHostOSExec{
				testBaseHost: testBaseHost{},
				osExecErr:    nil,
			},
			createGrpErr: errors.New(""),
		},
		authorized:   true,
		authorizeErr: nil,
	}
	e4 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, h4, false, addUserOptions)
	if e4 == nil {
		t.Errorf("Add User to Sytem did not return error for valid host but error from create group host")
	}

	h5 := &testPosixHostOSExec{
		testBaseHost: testBaseHost{},
		osExecErr:    nil,
	}
	e5 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, h5, true, addUserOptions)
	if e5 == nil {
		t.Errorf("Add User to Sytem did not return error for valid host but unimplemented create group host")
	}

	h6 := &testUserAuthorizeCreateGrpOSExecHost{
		testCreateGroupOSExecHost: testCreateGroupOSExecHost{
			testPosixHostOSExec: testPosixHostOSExec{
				testBaseHost: testBaseHost{},
				osExecErr:    errors.New(""),
			},
			createGrpErr: nil,
		},
		authorized:   true,
		authorizeErr: nil,
	}
	e6 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, h6, true, addUserOptions)
	if e6 == nil {
		t.Errorf("Add User to Sytem did not return error for valid host but error from OS exec")
	}

	h7 := &testCreateGroupHost{
		testBaseHost: testBaseHost{},
		createGrpErr: nil,
	}
	e7 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, h7, true, addUserOptions)
	if e7 == nil {
		t.Errorf("Add User to Sytem did not return error for valid cert but unimplemented OS exec Host")
	}

	validUserAuthorizeCreateGrpOSExecHost := &testUserAuthorizeCreateGrpOSExecHost{
		testCreateGroupOSExecHost: testCreateGroupOSExecHost{
			testPosixHostOSExec: testPosixHostOSExec{
				testBaseHost: testBaseHost{},
				osExecErr:    nil,
			},
			createGrpErr: nil,
		},
		authorized:   true,
		authorizeErr: nil,
	}

	e10 := DefaultPosixHostAddUserToSystem("valid_user", validPosixCert, validUserAuthorizeCreateGrpOSExecHost, false, addUserOptions)
	if e10 != nil {
		t.Errorf("Add User to Sytem returned error for valid host and  cert combinations")
	}
}

type testPosixGroupsCert struct {
	testPosixCert
	groups    []group.PosixGroup
	groupsErr error
}

func (c *testPosixGroupsCert) GetGroupsClaim() ([]group.PosixGroup, error) {
	return c.groups, c.groupsErr
}
func (c *testPosixGroupsCert) SetGroupsClaim([]group.PosixGroup) error {
	return nil
}

type testMissingHostsOSExecHost struct {
	testCreateGroupHost
	osExecErr error
}

func (c *testMissingHostsOSExecHost) PosixHostOSExec(stdInput []byte, cmdAndArgs ...string) (string, error) {
	return "", c.osExecErr
}

func TestDefaultPosixHostAddMissingGroupsFromCert(t *testing.T) {
	//DefaultPosixHostAddMissingGroupsFromCert(principal string, cert sshcert.CertPosixAccount, host PosixHost, groupAddCmdOptions *DefaultPosixAddGroupOptions) error {

	e1 := DefaultPosixHostAddMissingGroupsFromCert("", &testPosixCert{}, &testBaseHost{}, nil)
	if e1 != nil {
		t.Errorf("AddMissingGroupsFromCert errored for unimplemented posixGroupsClaimCert")
	}
	testErrGroupsClaimsCert := &testPosixGroupsCert{
		testPosixCert: testPosixCert{
			principal: strPtr("s"),
			uid:       ptrUint32(123),
			primGrp: &group.DefaultPosixGroup{
				Gid:  ptrUint16(123),
				Name: strPtr("s"),
			},
		},
		groups:    []group.PosixGroup{},
		groupsErr: errors.New(""),
	}
	validHost := &testMissingHostsOSExecHost{
		testCreateGroupHost: testCreateGroupHost{
			testBaseHost: testBaseHost{},
			createGrpErr: nil,
		},
		osExecErr: nil,
	}
	e2 := DefaultPosixHostAddMissingGroupsFromCert("", testErrGroupsClaimsCert, validHost, nil)
	if e2 == nil {
		t.Errorf("AddMissingGroupsFromCert did not error for errored out posixGroupsClaimCert and validHost")
	}

	validGroupsClaimsCert := &testPosixGroupsCert{
		testPosixCert: testPosixCert{
			principal: strPtr("s"),
			uid:       ptrUint32(123),
			primGrp: &group.DefaultPosixGroup{
				Gid:  ptrUint16(123),
				Name: strPtr("s"),
			},
		},
		groups: []group.PosixGroup{&group.DefaultPosixGroup{
			Gid:  ptrUint16(234),
			Name: strPtr("k"),
		},
		},
		groupsErr: nil,
	}
	unimplementedCreateGroupHost := &testBaseHost{}
	e3 := DefaultPosixHostAddMissingGroupsFromCert("", validGroupsClaimsCert, unimplementedCreateGroupHost, nil)
	if e3 == nil {
		t.Errorf("AddMissingGroupsFromCert did not error for unimplemented createGroupHost and validCert")
	}

	erroringCreateGrpHost := &testMissingHostsOSExecHost{
		testCreateGroupHost: testCreateGroupHost{
			testBaseHost: testBaseHost{},
			createGrpErr: errors.New(""),
		},
		osExecErr: nil,
	}
	e4 := DefaultPosixHostAddMissingGroupsFromCert("", validGroupsClaimsCert, erroringCreateGrpHost, nil)
	if e4 == nil {
		t.Errorf("AddMissingGroupsFromCert did not error for erroring createGroupHost and validCert")
	}

	erroringOsExecHost := &testMissingHostsOSExecHost{
		testCreateGroupHost: testCreateGroupHost{
			testBaseHost: testBaseHost{},
			createGrpErr: nil,
		},
		osExecErr: errors.New(""),
	}
	e5 := DefaultPosixHostAddMissingGroupsFromCert("", validGroupsClaimsCert, erroringOsExecHost, nil)
	if e5 == nil {
		t.Errorf("AddMissingGroupsFromCert did not error for erroring osExecHost and validCert")
	}

	e6 := DefaultPosixHostAddMissingGroupsFromCert("", validGroupsClaimsCert, validHost, nil)
	if e6 != nil {
		t.Errorf("AddMissingGroupsFromCert errorred for valid createGroupHost and validCert")
	}
}

type testOwnershipEntitlementsHost struct {
	testBaseHost
	entitlements []string
}

func (c *testOwnershipEntitlementsHost) PosixHostOwnershipEntitlements() []string {
	return c.entitlements
}

func TestDefaultPosixHostUserAuthorize(t *testing.T) {
	//DefaultPosixHostUserAuthorize(user string, cert sshcert.CertPosixAccount, host PosixHost) (bool, error)
	testErrGroupsClaimsCert := &testPosixGroupsCert{
		testPosixCert: testPosixCert{
			principal: strPtr("s"),
			uid:       ptrUint32(123),
			primGrp: &group.DefaultPosixGroup{
				Gid:  ptrUint16(123),
				Name: strPtr("s"),
			},
		},
		groups:    []group.PosixGroup{},
		groupsErr: errors.New(""),
	}
	validHost := &testOwnershipEntitlementsHost{
		testBaseHost: testBaseHost{},
		entitlements: []string{"k", "S"},
	}

	_, e1 := DefaultPosixHostUserAuthorize("", testErrGroupsClaimsCert, validHost)
	if e1 != nil {
		t.Errorf("User Authorize returned error for valid host and erroring out posixgroupsclaimscert")
	}

	erroringPrimaryGrpsPosixCert := &testPosixCert{
		principal: strPtr("s"),
		uid:       ptrUint32(123),
		primGrp:   nil,
	}
	_, e2 := DefaultPosixHostUserAuthorize("", erroringPrimaryGrpsPosixCert, validHost)
	if e2 == nil {
		t.Errorf("User Authorize did not return error for valid host and erroring out primarygroupsclaimscert")
	}
	secGrp1 := &group.DefaultPosixGroup{
		Gid:  ptrUint16(789),
		Name: strPtr("l"),
	}
	secGrp2 := &group.DefaultPosixGroup{
		Gid:  ptrUint16(234),
		Name: strPtr("k"),
	}
	secGrps := []group.PosixGroup{}
	secGrps = append(secGrps, secGrp1)
	secGrps = append(secGrps, secGrp2)
	validGrpsClaimsCert := &testPosixGroupsCert{
		testPosixCert: testPosixCert{
			principal: strPtr("s"),
			uid:       ptrUint32(123),
			primGrp: &group.DefaultPosixGroup{
				Gid:  ptrUint16(123),
				Name: strPtr("s"),
			},
		},
		groups:    secGrps,
		groupsErr: nil,
	}
	_, e3 := DefaultPosixHostUserAuthorize("", validGrpsClaimsCert, &testBaseHost{})
	if e3 == nil {
		t.Errorf("User Authorize did not return error for valid cert but unimplemented testOwnershipEntitlementsHost")
	}
	authorized, e4 := DefaultPosixHostUserAuthorize("", validGrpsClaimsCert, validHost)
	if e4 != nil {
		t.Errorf("User Authorize returned error for valid cert and valid ownershipEntitlementsHost")
	}
	if !authorized {
		t.Errorf("User Authorize did not authorize user for matching group in valid cert and valid ownershipEntitlementsHost")
	}
}

func TestDefaultPosixHostResetPasswd(t *testing.T) {
	//DefaultPosixHostResetPasswd(user string, passwdHash string, host PosixHost) error
	e1 := DefaultPosixHostResetPasswd("user", "$1", &testBaseHost{})
	if e1 == nil {
		t.Errorf("DefaultPosixHostResetPasswd did not return error for unimplemented PosixHostOSExecHost")
	}

	erroringPosixHostOSExecHost := &testPosixHostOSExec{
		testBaseHost: testBaseHost{},
		osExecErr:    errors.New(""),
	}
	e2 := DefaultPosixHostResetPasswd("user", "$1", erroringPosixHostOSExecHost)
	if e2 == nil {
		t.Errorf("DefaultPosixHostResetPasswd did not return error for erroring PosixHostOSExecHost")
	}

	validPosixHost := &testPosixHostOSExec{
		testBaseHost: testBaseHost{},
		osExecErr:    nil,
	}
	e3 := DefaultPosixHostResetPasswd("user", "$1", validPosixHost)
	if e3 != nil {
		t.Errorf("DefaultPosixHostResetPasswd returned error for valid PosixHostOSExecHost")
	}
}

func TestDefaultPosixHostCreateGroupIfNotExists(t *testing.T) {
	//DefaultPosixHostCreateGroupIfNotExists(group group.PosixGroup, host PosixHost,
	//	groupAddCmdOptions *DefaultPosixAddGroupOptions, usrgrpsLookup UsrsGrpsLookUp) error
	validGrpIDLookUp := &testUsrGrpLookUp{
		gidLookupErr: nil,
		gidLookupResult: &osuser.Group{
			Gid:  "133",
			Name: "grp1",
		},
	}
	posixGrp := &group.DefaultPosixGroup{
		Gid:  ptrUint16(133),
		Name: strPtr("grp1"),
	}
	e1 := DefaultPosixHostCreateGroupIfNotExists(posixGrp, &testBaseHost{}, nil, validGrpIDLookUp)
	if e1 != nil {
		t.Errorf("DefaultPosixHostCreateGroupIfNotExists returned error for matching posix grp and lookup results")
	}

	nonMatchingGrpNameIDLookUp := &testUsrGrpLookUp{
		gidLookupErr: nil,
		gidLookupResult: &osuser.Group{
			Gid:  "133",
			Name: "grp2",
		},
	}
	e2 := DefaultPosixHostCreateGroupIfNotExists(posixGrp, &testBaseHost{}, nil, nonMatchingGrpNameIDLookUp)
	if e2 == nil {
		t.Errorf("DefaultPosixHostCreateGroupIfNotExists returned nil error for valid posix grp but non matching lookup result")
	}

	noMatchGroupNameLookUp := &testUsrGrpLookUp{
		gidLookupErr:   errors.New(""),
		groupLookupErr: nil,
	}
	e3 := DefaultPosixHostCreateGroupIfNotExists(posixGrp, &testBaseHost{}, nil, noMatchGroupNameLookUp)
	if e3 == nil {
		t.Errorf("DefaultPosixHostCreateGroupIfNotExists returned nil error for valid posix grp and matching group name but non matching ID lookup result")
	}

	noMatchGroupLookUp := &testUsrGrpLookUp{
		gidLookupErr:   errors.New(""),
		groupLookupErr: errors.New(""),
	}
	groupAddCmdOptions := &DefaultPosixAddGroupOptions{
		ForceOption:  true,
		NonUniqueGID: true,
		PasswdHash:   "$2",
		SystemGroup:  true,
		ChrootDir:    "/var/",
	}
	erroringPosixHostOSExecHost := &testPosixHostOSExec{
		testBaseHost: testBaseHost{},
		osExecErr:    errors.New(""),
	}
	e4 := DefaultPosixHostCreateGroupIfNotExists(posixGrp, erroringPosixHostOSExecHost, groupAddCmdOptions, noMatchGroupLookUp)
	if e4 == nil {
		t.Errorf("DefaultPosixHostCreateGroupIfNotExists returned nil error for erroring posixHostOSExecHost")
	}

	e5 := DefaultPosixHostCreateGroupIfNotExists(posixGrp, &testBaseHost{}, groupAddCmdOptions, noMatchGroupLookUp)
	if e5 == nil {
		t.Errorf("DefaultPosixHostCreateGroupIfNotExists returned nil error for unimplemented posixHostOSExecHost")
	}

	validPosixHost := &testPosixHostOSExec{
		testBaseHost: testBaseHost{},
		osExecErr:    nil,
	}
	e6 := DefaultPosixHostCreateGroupIfNotExists(posixGrp, validPosixHost, groupAddCmdOptions, noMatchGroupLookUp)
	if e6 != nil {
		t.Errorf("DefaultPosixHostCreateGroupIfNotExists returned error for valid posixHostOSExecHost")
	}
}

type testEnvLookUp struct {
	keyVal string
	found  bool
}

func (c *testEnvLookUp) LookupEnv(key string) (string, bool) {
	return c.keyVal, c.found
}

type testOwnerEntitlementsKeyHost struct {
	testBaseHost
	key string
}

func (c *testOwnerEntitlementsKeyHost) PosixHostOwnershipEntitlementsKey() string {
	return c.key
}

type testEc2TagFetcherMatchingKey struct {
	result string
	err    error
}

func (c *testEc2TagFetcherMatchingKey) FetchEC2TagValueMatchingKey(key string, metadataClient EC2MetadataClient, ec2Service ec2iface.EC2API) (string, error) {
	return c.result, c.err
}

func TestDefaultPosixHostOwnershipEntitlements(t *testing.T) {
	//DefaultPosixHostOwnershipEntitlements(host PosixHost, envLookup OSEnvLookUp) []string
	res1 := DefaultPosixHostOwnershipEntitlements(&testBaseHost{}, &testEnvLookUp{}, &testEc2TagFetcherMatchingKey{})
	if res1 != nil {
		t.Errorf("OwnershipEntitlements result is not nil for unimplemened ownerEntitlementsKeyHost")
	}
	res2 := DefaultPosixHostOwnershipEntitlements(&testOwnerEntitlementsKeyHost{}, &testEnvLookUp{}, &testEc2TagFetcherMatchingKey{})
	if res2 != nil {
		t.Errorf("OwnershipEntitlements result is not nil for empty ownerEntitlementsKeyHost key value")
	}
	res3 := DefaultPosixHostOwnershipEntitlements(&testOwnerEntitlementsKeyHost{key: "env"}, &testEnvLookUp{keyVal: "dev:web:frontend", found: true}, &testEc2TagFetcherMatchingKey{result: "test"})
	if res3 == nil {
		t.Errorf("OwnershipEntitlements result nil for valid EnvLookUp result")
	}
}

type testExec struct{}

func (c *testExec) Command(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}

func TestDefaultPosixHostOSExec(t *testing.T) {
	validStdInput := []byte("swoossh\nssh\nsolved")
	validCmd := []string{"sh", "-c", "grep 'ssh'"}
	o1, e1 := DefaultPosixHostOSExec(&testBaseHost{}, &testExec{}, validStdInput, validCmd...)
	if e1 != nil {
		t.Errorf("DefaultPosixHostOSExec returned error for valid input and commands")
	}
	if o1 != "swoossh\nssh\n" {
		t.Errorf("Output from DefaultPosixHostOSExec does not match expectation for valid input and commands")
	}
}

type testMetadataClient struct {
	clientAvailable bool
	getMetadata     string
	getMetadataErr  error
}

func (c *testMetadataClient) Available() bool {
	return c.clientAvailable
}
func (c *testMetadataClient) GetMetadata(p string) (string, error) {
	return c.getMetadata, c.getMetadataErr
}

type testEC2Svc struct {
	ec2iface.EC2API
	output ec2.DescribeTagsOutput
	err    error
}

func (c *testEC2Svc) DescribeTags(input *ec2.DescribeTagsInput) (*ec2.DescribeTagsOutput, error) {
	output := c.output
	if input.NextToken == nil {
		output.SetNextToken("some token")
	}
	return &output, c.err
}

func TestDefaultFetchEC2TagValueMatchingKey(t *testing.T) {
	//DefaultFetchEC2TagValueMatchingKey(key string, metadataClient EC2MetadataClient, ec2Service ec2iface.EC2API) (string, error)
	unAvailableMetadataClient := &testMetadataClient{
		clientAvailable: false,
		getMetadata:     "i-12232somemore",
		getMetadataErr:  nil,
	}
	validEc2Svc := &testEC2Svc{
		output: ec2.DescribeTagsOutput{
			Tags: []*ec2.TagDescription{
				&ec2.TagDescription{
					Key:   strPtr("matchingKey"),
					Value: strPtr("matchingValue"),
				},
				&ec2.TagDescription{
					Key:   strPtr("notmatchingKey"),
					Value: strPtr("notmatchingValue"),
				},
			},
		},
		err: nil,
	}

	_, e1 := DefaultFetchEC2TagValueMatchingKey("matchingKey", unAvailableMetadataClient, validEc2Svc)
	if e1 == nil {
		t.Errorf("DefaultFetchEC2TagValueMatchingKey returned nil error for unavailable metadata client")
	}

	erroringMetadataClient := &testMetadataClient{
		clientAvailable: true,
		getMetadata:     "i-12232somemore",
		getMetadataErr:  errors.New(""),
	}
	_, e2 := DefaultFetchEC2TagValueMatchingKey("matchingKey", erroringMetadataClient, validEc2Svc)
	if e2 == nil {
		t.Errorf("DefaultFetchEC2TagValueMatchingKey returned nil error for erroring metadata client")
	}

	validMetadataClient := &testMetadataClient{
		clientAvailable: true,
		getMetadata:     "i-12232somemore",
		getMetadataErr:  nil,
	}
	erroringEc2Svc := &testEC2Svc{
		output: ec2.DescribeTagsOutput{
			Tags: []*ec2.TagDescription{
				&ec2.TagDescription{
					Key:   strPtr("matchingKey"),
					Value: strPtr("matchingValue"),
				},
				&ec2.TagDescription{
					Key:   strPtr("notmatchingKey"),
					Value: strPtr("notmatchingValue"),
				},
			},
		},
		err: errors.New(""),
	}
	_, e3 := DefaultFetchEC2TagValueMatchingKey("matchingKey", validMetadataClient, erroringEc2Svc)
	if e3 == nil {
		t.Errorf("DefaultFetchEC2TagValueMatchingKey returned nil error for erroring ec2 service client")
	}

	nonMatchingEc2Svc := &testEC2Svc{
		output: ec2.DescribeTagsOutput{
			Tags: []*ec2.TagDescription{
				&ec2.TagDescription{
					Key:   strPtr("doesNotMatch"),
					Value: strPtr("matchingValue"),
				},
				&ec2.TagDescription{
					Key:   strPtr("notmatchingKey"),
					Value: strPtr("notmatchingValue"),
				},
			},
		},
		err: nil,
	}
	result, e4 := DefaultFetchEC2TagValueMatchingKey("matchingKey", validMetadataClient, nonMatchingEc2Svc)
	if e4 != nil {
		t.Errorf("DefaultFetchEC2TagValueMatchingKey returned error for valid ec2 and metadata clients but non-matching results")
	}
	if result != "" {
		t.Errorf("DefaultFetchEC2TagValueMatchingKey returned result as matched for non-matching results")
	}

	match, e5 := DefaultFetchEC2TagValueMatchingKey("matchingKey", validMetadataClient, validEc2Svc)
	if e5 != nil {
		t.Errorf("DefaultFetchEC2TagValueMatchingKey returned error for valid ec2 and metadata clients and matching results")
	}
	if match != "matchingValue" {
		t.Errorf("DefaultFetchEC2TagValueMatchingKey returned result as unmatched for matching results")
	}
}
