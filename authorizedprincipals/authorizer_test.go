package authorizedprincipals

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ChandraNarreddy/swoossh/sshcert"
)

func strPtr(s string) *string {
	return &s
}

type testCertClaims struct {
	principal *string
}

func (c *testCertClaims) GetPrincipalName() (string, error) {
	p := c.principal
	if p == nil {
		return "", fmt.Errorf("principal is nil")
	}
	return *p, nil
}
func (c *testCertClaims) SetPrincipalName(p string) error {
	if p == "return error" {
		c.principal = nil
		return fmt.Errorf("Some error")
	}
	c.principal = &p
	return nil
}

type testHostBase struct {
	buf        string
	targetUser string
}

func (c *testHostBase) PrintAuthorizedPrincipalsFile(user string, cert sshcert.Cert) error {
	c.buf = fmt.Sprintf("%s", user)
	return nil
}

func (c *testHostBase) GetSSHCmdTargetUser() string {
	return c.targetUser
}

type treatMissingPrincipalAsLocalUserHost struct {
	localUser string
	testHostBase
}

func (c *treatMissingPrincipalAsLocalUserHost) TreatMissingPrincpalInCertAsLocalUser() string {
	return c.localUser
}

type matchUserClaimsToExistingAccountHost struct {
	testHostBase
	matchErr  error
	match     bool
	matchUser string
}

func (c *matchUserClaimsToExistingAccountHost) MatchUserClaimToExistingAccount(cert sshcert.Cert) (bool, string, error) {
	if c.matchErr != nil {
		return false, "", c.matchErr
	}
	return c.match, c.matchUser, nil
}

type syncUsersGroupMembershipsHost struct {
	matchUserClaimsToExistingAccountHost
	sync bool
}

func (c *syncUsersGroupMembershipsHost) SyncUsersGroupMemberships() bool {
	return c.sync
}

type userGroupMembershipModifyHost struct {
	syncUsersGroupMembershipsHost
	groupMembershipModifyErr error
}

func (c *userGroupMembershipModifyHost) UserGroupMembershipModify(string, sshcert.Cert) error {
	return c.groupMembershipModifyErr
}

type syncUserSudoRulesHost struct {
	matchUserClaimsToExistingAccountHost
	sync bool
}

func (c *syncUserSudoRulesHost) SyncUserSudoRules() bool {
	return c.sync
}

type modifySudoRulesHost struct {
	syncUserSudoRulesHost
	modifySudoRulesErr error
}

func (c *modifySudoRulesHost) ModifySudoRules(string, sshcert.Cert) error {
	return c.modifySudoRulesErr
}

type createUserIfNotExistsHost struct {
	testHostBase
	create bool
}

func (c *createUserIfNotExistsHost) CreateUserIfNotExists() bool {
	return c.create
}

type addUserToSystemHost struct {
	createUserIfNotExistsHost
	addUserErr error
}

func (c *addUserToSystemHost) AddUserToSystem(userLogin string, cert sshcert.Cert) error {
	return c.addUserErr
}

type createMissingGroupsHost struct {
	addUserToSystemHost
	create bool
}

func (c *createMissingGroupsHost) CreateMissingGroups() bool {
	return c.create
}

type addMissingGroupsHost struct {
	createMissingGroupsHost
	addMissingGrpsErr error
}

func (c *addMissingGroupsHost) AddMissingGroups(principal string, cert sshcert.Cert) error {
	return c.addMissingGrpsErr
}

type addSudoCmdHost struct {
	addUserToSystemHost
	add bool
}

func (c *addSudoCmdHost) AddSudoCmd() bool {
	return c.add
}

type appendSudoCmdHost struct {
	addSudoCmdHost
	appendSudoCmdErr error
}

func (c *appendSudoCmdHost) AppendSudoCmd(principal string, cert sshcert.Cert) error {
	return c.appendSudoCmdErr
}

func TestDefaultAuthorizerAuthorizeUser(t *testing.T) {
	a1 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{},
	}
	if a1.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for certclaims with nil prinicpalName")
	}

	emptyPrincipal := ""
	a2 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: &emptyPrincipal},
		Host:       &testHostBase{targetUser: "claims"},
	}
	if a2.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for empty certClaims and unimplemented TreatMissingPrincpalInCertAsLocalUser combination")
	}

	a3a := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: &emptyPrincipal},
		Host:       &treatMissingPrincipalAsLocalUserHost{localUser: "321", testHostBase: testHostBase{targetUser: "123", buf: ""}},
	}
	if a3a.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for empty certClaims but mismatching TreatMissingPrincpalInCertAsLocalUser and targetUser")
	}

	a3b := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: &emptyPrincipal},
		Host:       &treatMissingPrincipalAsLocalUserHost{localUser: "123", testHostBase: testHostBase{targetUser: "123", buf: ""}},
	}
	if a3b.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for empty certClaims and TreatMissingPrincpalInCertAsLocalUser implemented host combination")
	}

	a4 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &matchUserClaimsToExistingAccountHost{
			testHostBase: testHostBase{targetUser: "claims"},
			matchErr:     fmt.Errorf("Match Error"),
			match:        true,
			matchUser:    "",
		},
	}
	if a4.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for MatchToExistingAccount error")
	}

	a5 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &matchUserClaimsToExistingAccountHost{
			testHostBase: testHostBase{targetUser: "claims"},
			matchErr:     nil,
			match:        false,
			matchUser:    "",
		},
	}
	if a5.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for failed MatchToExistingAccount and CreateUserIfNotExists not implemented")
	}

	a6 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &matchUserClaimsToExistingAccountHost{
			testHostBase: testHostBase{targetUser: "claims"},
			matchErr:     nil,
			match:        true,
			matchUser:    "",
		},
	}
	if a6.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for passed MatchToExistingAccount")
	}

	a7 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &syncUsersGroupMembershipsHost{
			matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
				testHostBase: testHostBase{targetUser: "claims"},
				matchErr:     nil,
				match:        true,
				matchUser:    "user",
			},
			sync: false,
		},
	}
	if a7.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for passed MatchToExistingAccount and syncUsersGroupMemberships set to false")
	}

	a8 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &syncUsersGroupMembershipsHost{
			matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
				testHostBase: testHostBase{targetUser: "claims"},
				matchErr:     nil,
				match:        true,
				matchUser:    "user",
			},
			sync: true,
		},
	}
	if a8.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for passed MatchToExistingAccount but missing UserGroupMembershipModify implementation")
	}

	a9 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &userGroupMembershipModifyHost{
			syncUsersGroupMembershipsHost: syncUsersGroupMembershipsHost{
				matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
					testHostBase: testHostBase{targetUser: "claims"},
					matchErr:     nil,
					match:        true,
					matchUser:    "user",
				},
				sync: true,
			},
			groupMembershipModifyErr: errors.New(""),
		},
	}
	if a9.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for passed MatchToExistingAccount but groupMembershipModify Error")
	}

	a10 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &userGroupMembershipModifyHost{
			syncUsersGroupMembershipsHost: syncUsersGroupMembershipsHost{
				matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
					testHostBase: testHostBase{targetUser: "claims"},
					matchErr:     nil,
					match:        true,
					matchUser:    "user",
				},
				sync: true,
			},
			groupMembershipModifyErr: nil,
		},
	}
	if a10.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser did not throw error for passed MatchToExistingAccount and nil groupMembershipModify Error")
	}

	a11 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &syncUserSudoRulesHost{
			matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
				testHostBase: testHostBase{targetUser: "claims"},
				matchErr:     nil,
				match:        true,
				matchUser:    "user",
			},
			sync: false,
		},
	}
	if a11.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for passed MatchToExistingAccount and syncSudoRules set to false")
	}

	a12 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &syncUserSudoRulesHost{
			matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
				testHostBase: testHostBase{targetUser: "claims"},
				matchErr:     nil,
				match:        true,
				matchUser:    "user",
			},
			sync: true,
		},
	}
	if a12.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for passed MatchToExistingAccount but missing ModifySudoRules implementation")
	}

	a13 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &modifySudoRulesHost{
			syncUserSudoRulesHost: syncUserSudoRulesHost{
				matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
					testHostBase: testHostBase{targetUser: "claims"},
					matchErr:     nil,
					match:        true,
					matchUser:    "user",
				},
				sync: true,
			},
			modifySudoRulesErr: errors.New(""),
		},
	}
	if a13.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for passed MatchToExistingAccount but modifySudoRulesErr Error")
	}

	a14 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &modifySudoRulesHost{
			syncUserSudoRulesHost: syncUserSudoRulesHost{
				matchUserClaimsToExistingAccountHost: matchUserClaimsToExistingAccountHost{
					testHostBase: testHostBase{targetUser: "claims"},
					matchErr:     nil,
					match:        true,
					matchUser:    "user",
				},
				sync: true,
			},
			modifySudoRulesErr: nil,
		},
	}
	if a14.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for passed MatchToExistingAccount and nil modifySudoRulesErr Error")
	}

	a15 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("notClaims")},
		Host: &matchUserClaimsToExistingAccountHost{
			testHostBase: testHostBase{targetUser: "claims"},
			matchErr:     nil,
			match:        true,
			matchUser:    "user",
		},
	}
	if a15.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for passed MatchToExistingAccount but mismatched targetUser and principal")
	}

	a21 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &createUserIfNotExistsHost{
			testHostBase: testHostBase{targetUser: "claims"},
			create:       false,
		},
	}
	if a21.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for unimplemented MatchToExistingAccount and disabled createUserIfNotExists")
	}

	a22 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &createUserIfNotExistsHost{
			testHostBase: testHostBase{targetUser: "claims"},
			create:       true,
		},
	}
	if a22.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for createUserIfNotExists but unimplemented addUserToSystem")
	}

	a23 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &addUserToSystemHost{
			createUserIfNotExistsHost: createUserIfNotExistsHost{
				testHostBase: testHostBase{targetUser: "claims"},
				create:       true,
			},
			addUserErr: errors.New(""),
		},
	}
	if a23.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for createUserIfNotExists but errored out addUserToSystem")
	}

	a24 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &addUserToSystemHost{
			createUserIfNotExistsHost: createUserIfNotExistsHost{
				testHostBase: testHostBase{targetUser: "claims"},
				create:       true,
			},
			addUserErr: nil,
		},
	}
	if a24.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for createUserIfNotExists and nil addUserToSystem error")
	}

	a25 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &createMissingGroupsHost{
			addUserToSystemHost: addUserToSystemHost{
				createUserIfNotExistsHost: createUserIfNotExistsHost{
					testHostBase: testHostBase{targetUser: "claims"},
					create:       true,
				},
				addUserErr: nil,
			},
			create: false,
		},
	}
	if a25.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for createUserIfNotExists and createmissinggroups set to false")
	}

	a26 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &createMissingGroupsHost{
			addUserToSystemHost: addUserToSystemHost{
				createUserIfNotExistsHost: createUserIfNotExistsHost{
					testHostBase: testHostBase{targetUser: "claims"},
					create:       true,
				},
				addUserErr: nil,
			},
			create: true,
		},
	}
	if a26.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for createUserIfNotExists but missing addmissinggroups implementation")
	}

	a27 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &addMissingGroupsHost{
			createMissingGroupsHost: createMissingGroupsHost{
				addUserToSystemHost: addUserToSystemHost{
					createUserIfNotExistsHost: createUserIfNotExistsHost{
						testHostBase: testHostBase{targetUser: "claims"},
						create:       true,
					},
					addUserErr: nil,
				},
				create: true,
			},
			addMissingGrpsErr: errors.New(""),
		},
	}
	if a27.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for createUserIfNotExists but addmissinggroups erroring out")
	}

	a28 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &addMissingGroupsHost{
			createMissingGroupsHost: createMissingGroupsHost{
				addUserToSystemHost: addUserToSystemHost{
					createUserIfNotExistsHost: createUserIfNotExistsHost{
						testHostBase: testHostBase{targetUser: "claims"},
						create:       true,
					},
					addUserErr: nil,
				},
				create: true,
			},
			addMissingGrpsErr: nil,
		},
	}
	if a28.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for createUserIfNotExists and nil addmissinggroups error")
	}

	a29 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &addSudoCmdHost{
			addUserToSystemHost: addUserToSystemHost{
				createUserIfNotExistsHost: createUserIfNotExistsHost{
					testHostBase: testHostBase{targetUser: "claims"},
					create:       true,
				},
				addUserErr: nil,
			},
			add: false,
		},
	}
	if a29.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for createUserIfNotExists and addSudoCmd set to false")
	}

	a30 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &addSudoCmdHost{
			addUserToSystemHost: addUserToSystemHost{
				createUserIfNotExistsHost: createUserIfNotExistsHost{
					testHostBase: testHostBase{},
					create:       true,
				},
				addUserErr: nil,
			},
			add: true,
		},
	}
	if a30.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for createUserIfNotExists but missing appendSudoCmd implementation")
	}

	a31 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &appendSudoCmdHost{
			addSudoCmdHost: addSudoCmdHost{
				addUserToSystemHost: addUserToSystemHost{
					createUserIfNotExistsHost: createUserIfNotExistsHost{
						testHostBase: testHostBase{},
						create:       true,
					},
					addUserErr: nil,
				},
				add: true,
			},
			appendSudoCmdErr: errors.New(""),
		},
	}
	if a31.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for createUserIfNotExists but appendSudoCmd erroring out")
	}

	a32 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("claims")},
		Host: &appendSudoCmdHost{
			addSudoCmdHost: addSudoCmdHost{
				addUserToSystemHost: addUserToSystemHost{
					createUserIfNotExistsHost: createUserIfNotExistsHost{
						testHostBase: testHostBase{targetUser: "claims"},
						create:       true,
					},
					addUserErr: nil,
				},
				add: true,
			},
			appendSudoCmdErr: nil,
		},
	}
	if a32.AuthorizeUser() != nil {
		t.Errorf("AuthorizeUser threw error for createUserIfNotExists and nil appendSudoCmd error")
	}

	a33 := &DefaultAuthorizer{
		CertClaims: &testCertClaims{principal: strPtr("notClaims")},
		Host: &appendSudoCmdHost{
			addSudoCmdHost: addSudoCmdHost{
				addUserToSystemHost: addUserToSystemHost{
					createUserIfNotExistsHost: createUserIfNotExistsHost{
						testHostBase: testHostBase{targetUser: "claims"},
						create:       true,
					},
					addUserErr: nil,
				},
				add: true,
			},
			appendSudoCmdErr: nil,
		},
	}
	if a33.AuthorizeUser() == nil {
		t.Errorf("AuthorizeUser did not throw error for mismatching principal and targetUser")
	}

}
