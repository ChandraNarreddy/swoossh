package authorizedprincipals

import (
	"fmt"
	"log"

	"github.com/ChandraNarreddy/swoossh/sshcert"
)

//Authorizer is the meta interface that needs to be implemented
//by anyone that wants to plug in their custom authorization logic
//Any implementation must authorize the principal presented in the
//SSH certificate and eventually print the principal to standard
//output as per the https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand
type Authorizer interface {
	AuthorizeUser() error
}

//DefaultAuthorizer is the default implementation of the authorizer interface.
//certClaims is a type that implements the Cert interface
//host is a type that implements the Host interface
type DefaultAuthorizer struct {
	CertClaims sshcert.Cert
	Host       Host
}

//AuthorizeUser is the default implementation
func (c *DefaultAuthorizer) AuthorizeUser() error {
	principal, err := c.CertClaims.GetPrincipalName()
	if err != nil {
		log.Printf("Errored out fetching principal from cert, aborting")
		return fmt.Errorf("Errored out fetching principal from cert, aborting")
	}
	targetUser := c.Host.GetSSHCmdTargetUser()
	var principalTargetMatch bool
	if principal == targetUser {
		principalTargetMatch = true
	} else {
		log.Printf("SSH target user %s does not match with principal %s from certificate", targetUser, principal)
	}
	if principal == "" {
		if missingPrincipal, ok := c.Host.(TreatMissingPrincpalInCertAsLocalUser); ok {
			user := missingPrincipal.TreatMissingPrincpalInCertAsLocalUser()
			log.Printf("Principal element is empty in the cert, considering the principal as %s", user)
			if targetUser == user {
				return c.Host.PrintAuthorizedPrincipalsFile(user, c.CertClaims)
			} else {
				log.Printf("Target user %s and principal %s mismatch", targetUser, user)
				return fmt.Errorf("Target user %s and principal %s mismatch. Denying login", targetUser, user)
			}
		} else {
			//deny login since TreatMissingPrincpalInCertAs option is not exercised
			log.Print("Principal element is empty in the cert but TreatMissingPrincpalInCertAs option not exercised")
			return fmt.Errorf("Principal element is empty in the cert but TreatMissingPrincpalInCertAs option not exercised")
		}
	}

	//Now verify if cert claims in cert match up to any existing account
	if existingAccountMatch, ok := c.Host.(MatchCertClaimToAnExistingAccount); ok {
		userMatchFound, user, err := existingAccountMatch.MatchUserClaimToExistingAccount(c.CertClaims)
		if err != nil {
			log.Print("MatchToExistingAccount routine errored out. Aborting")
			return fmt.Errorf("MatchToExistingAccount routine errored out. Aborting")
		}
		if userMatchFound {
			log.Printf("User claims matched up to user %s locally, proceeding further", user)
			if principalTargetMatch {
				//re-sync user's group membership here based on the claims presented
				if syncUsersGroupMembershipsOption, ok := c.Host.(SyncUsersGroupMemberships); ok {
					if syncUsersGroupMembershipsOption.SyncUsersGroupMemberships() {
						if userGroupMembershipModifyImpl, ok := c.Host.(UserGroupMembershipModify); ok {
							userGroupMembershipModifyErr := userGroupMembershipModifyImpl.UserGroupMembershipModify(principal, c.CertClaims)
							if userGroupMembershipModifyErr != nil {
								log.Print("Error encountered while modifying user's group memberships. Aborting")
								return fmt.Errorf("Error encountered while modifying user's group memberships. Aborting")
							}
						} else {
							log.Print("UserGroupMembershipModify implementation missing. Aborting")
							return fmt.Errorf("UserGroupMembershipModify implementation missing. Aborting")
						}
					} else {
						log.Print("SyncUsersGroupMemberships option explicitly disabled.")
					}
				} else {
					log.Print("SyncUsersGroupMemberships option not exercised.")
				}
				//re-sync user's sudo rules here based on the claims presented
				if syncUserSudoRulesOption, ok := c.Host.(SyncUserSudoRules); ok {
					if syncUserSudoRulesOption.SyncUserSudoRules() {
						if modifySudoRulesImpl, ok := c.Host.(ModifySudoRules); ok {
							modifySudoRulesErr := modifySudoRulesImpl.ModifySudoRules(principal, c.CertClaims)
							if modifySudoRulesErr != nil {
								log.Print("Error encountered while modifying sudo rules. Aborting")
								return fmt.Errorf("Error encountered while modifying sudo rules. Aborting")
							}
						} else {
							log.Print("ModifySudoRules implementation missing. Aborting")
							return fmt.Errorf("ModifySudoRules implementation missing. Aborting")
						}
					} else {
						log.Print("SyncUserSudoRules option explicitly disabled.")
					}
				} else {
					log.Print("SyncUserSudoRules option not exercised.")
				}
				// prepare the AuthPrincipalFile here for user and stdprint
				return c.Host.PrintAuthorizedPrincipalsFile(user, c.CertClaims)
			} else {
				log.Printf("User claims match found locally but SSH target user %s does not match claimed principal %s", targetUser, user)
				return fmt.Errorf("User claims match found locally but SSH target user %s does not match claimed principal %s", targetUser, user)
			}
		} else {
			log.Print("User claims did not match to any user locally")
		}
	} else {
		log.Print("MatchUserClaimsToExistingUsers interface not implemented, checking if createUserOption is exercised")
	}

	//Principal match not found on host or matching not implemented, check if CreateUserIfNotExists option is enabled
	if createUserOption, ok := c.Host.(CreateUserIfNotExists); ok {
		if createUserOption.CreateUserIfNotExists() {
			log.Print("CreateUserIfNotExists option selected, proceeding to create user")
			//proceeding to create user now
			if addUserImpl, ok := c.Host.(AddUserToSystem); ok {
				//addUserImpl call here
				addUserErr := addUserImpl.AddUserToSystem(principal, c.CertClaims)
				if addUserErr != nil {
					log.Printf("Error encountered while adding user %s to system. Aborting", principal)
					return fmt.Errorf("Error encountered while adding user %s to system. Aborting", principal)
				}
				// Check if CreateMissingGroups option is exercised
				if createMissingGroupsOption, ok := c.Host.(CreateMissingGroups); ok {
					if createMissingGroupsOption.CreateMissingGroups() {
						log.Print("CreateMissingGroups option selected, proceeding to create missing groups")
						//Check if AddMissingGroups interface is implemented
						if addMissingGroupImpl, ok := c.Host.(AddMissingGroups); ok {
							addMissingGroupsErr := addMissingGroupImpl.AddMissingGroups(principal, c.CertClaims)
							if addMissingGroupsErr != nil {
								log.Print("Error encountered while adding missing groups to system. Aborting")
								return fmt.Errorf("Error encountered while adding missing groups to system. Aborting")
							}
						} else {
							log.Print("AddMissingGroups implementation missing. Aborting")
							return fmt.Errorf("AddMissingGroups implementation missing. Aborting")
						}
					} else {
						log.Print("CreateGroupsIfNotExists option explicitly disabled.")
					}
				} else {
					log.Print("CreateMissingGroups option not exercised")
				}

				//Check if AddSudoCmd option is exercised
				if addSudoCmdOption, ok := c.Host.(AddSudoCmd); ok {
					if addSudoCmdOption.AddSudoCmd() {
						log.Print("AddSudoCmd option selected, proceeding to add sudo command")
						//Check if AppendSudoCmd interface is implemented
						if appendSudoCmdImp, ok := c.Host.(AppendSudoCmd); ok {
							appendSudoCmdErr := appendSudoCmdImp.AppendSudoCmd(principal, c.CertClaims)
							if appendSudoCmdErr != nil {
								log.Print("Error encountered while adding sudo commands to system. Aborting")
								return fmt.Errorf("Error encountered while adding sudo commands to system. Aborting")
							}
						} else {
							log.Print("AppendSudoCmd implementation missing. Aborting")
							return fmt.Errorf("AppendSudoCmd implementation missing. Aborting")
						}
					} else {
						log.Print("AddSudoCmd option explicitly disabled.")
					}
				} else {
					log.Print("AddSudoCmd option not exercised")
				}
				if principalTargetMatch {
					return c.Host.PrintAuthorizedPrincipalsFile(principal, c.CertClaims)
				} else {
					log.Printf("Target user %s and principal %s mismatch", targetUser, principal)
					return fmt.Errorf("Target user %s and principal %s mismatch. Denying login", targetUser, principal)
				}

			} else {
				//AddUser is not implemented. Fail and deny
				log.Print("AddUser implementation is missing. Fail safe to deny")
				return fmt.Errorf("AddUser implementation is missing. Fail safe to deny")
			}
		} else {
			log.Print("New account creation disabled explicitly, denying login")
			return fmt.Errorf("New account creation disabled explicitly, denying login")
		}
	} else {
		log.Print("CreateUserIfNotExists choice not exercised, denying login by default")
		return fmt.Errorf("CreateUserIfNotExists choice not exercised, denying login by default")
	}

}
