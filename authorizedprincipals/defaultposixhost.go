package authorizedprincipals

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	osuser "os/user"
	"strconv"
	"strings"
	"time"

	group "github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/sshcert"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

type UsrsGrpsLookUp interface {
	Lookup(username string) (*osuser.User, error)
	LookupGroupId(gid string) (*osuser.Group, error)
	LookupGroup(name string) (*osuser.Group, error)
}

type OSExec interface {
	Command(name string, arg ...string) *exec.Cmd
}

type OSEnvLookUp interface {
	LookupEnv(key string) (string, bool)
}

type EC2MetadataClient interface {
	Available() bool
	GetMetadata(p string) (string, error)
}

type Ec2TagFetcherMatchingKey interface {
	FetchEC2TagValueMatchingKey(key string, metadataClient EC2MetadataClient, ec2Service ec2iface.EC2API) (string, error)
}

// ref
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
// https://man7.org/linux/man-pages/man1/ssh-keygen.1.html
// https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand

//AddPosixUserOptions allows to set options as per the useradd utility.
//userID (UID) for the user account. If not set, the system will assign one automatically
//primaryGroupID (gid). If not set, the system will assign one automatically
//defaultPasswdHash is the default password hash for each account.
//defaultPasswdHash value is overridden by that fetched from cert's GetLatestPasswdHash implementation.
//Please note that accounts created without passwd might have constraints with login. Cert based SSH should work though.
//createHome is a flag to instruct whether to create home dir or not.
//If createHome is set to true, the baseDir for the user needs to be set.
//expireData allows to set to occur when the user account needs to be expired
//loginShell is the shell for the user. If none  is specified, the system default will be applied.
//systemAccount allows to specify if the user account is a system account
type DefaultPosixAddUserOptions struct {
	DefaultPasswdHash *string //this is not a very secure option. Use this at own risk
	CreateHome        bool
	BaseHomeDir       string
	ExpireDate        *time.Time
	LoginShell        string
	SystemAccount     bool
}

//AddPosixGroupOptions as per the Posix groupAdd command
//force option causes to exit with success if group already exists. Any GID passed is ignored.
//nonUniqueGID allows to add group with non-unique GID, false  by  default
//passwdHash allows to set a password for the group, default is disabled
//systemGroup when true will create the GID within the system group ID ranges
//chrootDir is for applying changes in this chrooted dir path
type DefaultPosixAddGroupOptions struct {
	ForceOption  bool
	NonUniqueGID bool
	PasswdHash   string
	SystemGroup  bool
	ChrootDir    string
}

//DefaulPosixtHost creates a Host implementation tuned for POSIX systems.
//createUserIfNotExistsOption for whether to create user or not if the user account is not created already at the time of login
//disableNewAccountAuthorization is a flag instructing whether the new user needs to  be authorized before adding to the system
//hostOwnershipEntitlementsKey is the string key to lookup for ownership entitlement values available to the host. ex: {"team":"website"} or {"group":"sre/prod"}
//resetPasswdWithLatestFromCert is a flag which instructs to reset the password with the latest value from the certificate
//userAddCmdOptions are options as per the useradd posix system utility
//createMissingGroups option to allow creating any missing groups from the system
type DefaultPosixtHost struct {
	CreateUserIfNotExistsOption    bool
	DisableNewAccountAuthorization bool
	HostOwnershipEntitlementsKey   string
	SSHCmdTargetUser               string
	ResetPasswdWithLatestFromCert  bool
	UserAddCmdOptions              *DefaultPosixAddUserOptions
	AddMissingGroupsFromCert       bool
	GroupAddCmdOptions             *DefaultPosixAddGroupOptions
	OSLookup                       UsrsGrpsLookUp
	Exec                           OSExec
	EnvLookUp                      OSEnvLookUp
	Ec2TagFetcherForKey            Ec2TagFetcherMatchingKey
}

func (c *DefaultPosixtHost) CreateUserIfNotExists() bool {
	return DefaultPosixHostCreateUserIfNotExists(c)
}

func (c *DefaultPosixtHost) CreateMissingGroups() bool {
	return DefaultPosixHostCreateMissingGroups(c)
}

func (c *DefaultPosixtHost) PrintAuthorizedPrincipalsFile(user string, cert sshcert.Cert) error {
	return DefaultPosixHostPrintAuthorizedPrincipalsFile(user, cert, c)
}

func (c *DefaultPosixtHost) MatchUserClaimToExistingAccount(cert sshcert.Cert) (bool, string, error) {
	return DefaultPosixHostMatchCertClaimToAnExistingAccount(cert, c, c.ResetPasswdWithLatestFromCert, c.OSLookup)
}

func (c *DefaultPosixtHost) PosixHostUserAuthorize(user string, cert sshcert.CertPosixAccount) (bool, error) {
	return DefaultPosixHostUserAuthorize(user, cert, c)
}

func (c *DefaultPosixtHost) AddUserToSystem(userLogin string, cert sshcert.Cert) error {
	return DefaultPosixHostAddUserToSystem(userLogin, cert, c, c.DisableNewAccountAuthorization, c.UserAddCmdOptions)
}

func (c *DefaultPosixtHost) PosixHostOwnershipEntitlements() []string {
	return DefaultPosixHostOwnershipEntitlements(c, c.EnvLookUp, c.Ec2TagFetcherForKey)
}

func (c *DefaultPosixtHost) PosixHostOwnershipEntitlementsKey() string {
	return DefaultPosixHostPosixHostOwnershipEntitlementsKey(c)
}

func (c *DefaultPosixtHost) AddMissingGroups(principal string, cert sshcert.Cert) error {
	return DefaultPosixHostAddMissingGroupsFromCert(principal, cert, c, c.GroupAddCmdOptions)
}

func (c *DefaultPosixtHost) PosixHostResetPasswd(user string, passwdHash string) error {
	return DefaultPosixHostResetPasswd(user, passwdHash, c)
}

func (c *DefaultPosixtHost) PosixHostCreateGroupIfNotExists(group group.PosixGroup) error {
	return DefaultPosixHostCreateGroupIfNotExists(group, c, c.GroupAddCmdOptions, c.OSLookup)
}

func (c *DefaultPosixtHost) PosixHostOSExec(stdInput []byte, cmdAndArgs ...string) (string, error) {
	return DefaultPosixHostOSExec(c, c.Exec, stdInput, cmdAndArgs...)
}

func (c *DefaultPosixtHost) GetSSHCmdTargetUser() string {
	return DefaultPosixHostGetSSHCmdTargetUser(c)
}

func DefaultPosixHostGetSSHCmdTargetUser(host *DefaultPosixtHost) string {
	return host.SSHCmdTargetUser
}

func DefaultPosixHostCreateUserIfNotExists(host *DefaultPosixtHost) bool {
	if !host.CreateUserIfNotExistsOption {
		return false
	}
	return true
}

func DefaultPosixHostCreateMissingGroups(host *DefaultPosixtHost) bool {
	if !host.AddMissingGroupsFromCert {
		return false
	}
	return true
}

func DefaultPosixHostPosixHostOwnershipEntitlementsKey(host *DefaultPosixtHost) string {
	return host.HostOwnershipEntitlementsKey
}

//DefaultPosixPrintAuthorizedPrincipalsFile
func DefaultPosixHostPrintAuthorizedPrincipalsFile(user string, cert sshcert.Cert, host PosixHost) error {
	_, err := fmt.Printf("%s", user)
	return err
}

//DefaultPosixMatchCertClaimToAnExistingAccount
func DefaultPosixHostMatchCertClaimToAnExistingAccount(cert sshcert.Cert, host PosixHost, resetPasswdWithLatestFromCert bool, usrgrpsLookup UsrsGrpsLookUp) (bool, string, error) {
	user, err := cert.GetPrincipalName()
	if err != nil {
		log.Print("Errored out fetching user principal from certificate")
		return false, "", err
	}
	var uid uint32
	if posixCert, ok := cert.(sshcert.CertPosixAccount); !ok {
		log.Print("Certificate passed does not implement PosixCert interface. Cannot proceed to match with existing account")
		return false, "", fmt.Errorf("Certificate passed does not implement PosixCert interface. Cannot proceed to match with existing account")
	} else {
		var err error
		uid, err = posixCert.GetUIDClaim()
		if err != nil {
			log.Print("Errored out fetching uid from certificate")
			return false, "", err
		}
	}
	userIDString := strconv.FormatUint(uint64(uid), 10)
	lookup, err := usrgrpsLookup.Lookup(user)
	if err != nil {
		log.Print("Failed to find matching user for principal in certificate")
		return false, "", nil
	}
	if lookup.Uid == userIDString {
		log.Printf("Matched principal to account %s on the sytem", lookup.Username)
		// Check to see if the GetLatestPasswdHash option is exercised
		if latestPasswdHashImpl, ok := cert.(sshcert.GetLatestPasswdHash); ok && resetPasswdWithLatestFromCert {
			passwdHash, latestPasswdHashErr := latestPasswdHashImpl.GetLatestPasswdHash()
			if latestPasswdHashErr != nil {
				log.Print("GetLatestPasswdHash errored out, could not get latest password to attempt reset, Aborting login")
				return false, "", latestPasswdHashErr
			}
			if resetPasswdImpl, ok := host.(PosixHostResetPasswd); ok {
				resetPasswdErr := resetPasswdImpl.PosixHostResetPasswd(user, passwdHash)
				if resetPasswdErr != nil {
					log.Print("PosixHostResetPasswd errored out, could not reset password, Aborting login")
					return false, "", resetPasswdErr
				}
			} else {
				log.Print("ResetPasswdWithLatestFromCert enabled but implementation not found. Aborting login")
				return false, "", fmt.Errorf("ResetPasswdWithLatestFromCert enabled but implementation not found. Aborting login")
			}
		} else if resetPasswdWithLatestFromCert {
			log.Print("ResetPasswdWithLatestFromCert enabled but GetLatestPasswdHash is not implemented on cert")
		} else if ok {
			log.Print("GetLatestPasswdHash implemented but ResetPasswdWithLatestFromCert option is not selected")
		}
		return true, lookup.Username, nil
	} else {
		log.Printf("Matching user found for principal in certificate but uid does not match that from certificate - %s", userIDString)
		return false, "", nil
	}
}

//DefaultPosixAddUserToSystem
func DefaultPosixHostAddUserToSystem(userLogin string, cert sshcert.Cert,
	host PosixHost, disableNewAccountAuthorization bool, userAddCmdOptions *DefaultPosixAddUserOptions) error {
	//Check if authorization is sought
	posixCert, ok := cert.(sshcert.CertPosixAccount)
	if !ok {
		log.Print("Certificate passed does not implement CertPosixAccount interface. Cannot add user")
		return fmt.Errorf("Certificate passed does not implement CertPosixAccount interface. Cannot add user")
	}
	if !disableNewAccountAuthorization {
		if userAuthorizer, ok := host.(PosixHostUserAuthorize); ok {
			authorized, authorizerErr := userAuthorizer.PosixHostUserAuthorize(userLogin, posixCert)
			if authorizerErr != nil {
				log.Print("PosixHostUserAuthorize errored out, failed to add user")
				return fmt.Errorf("PosixHostUserAuthorize errored out, failed to add user")
			} else {
				if authorized {
					log.Print("User authorized, proceeding with user addition")
				} else {
					log.Print("User not authorized, cancelling user creation")
					return fmt.Errorf("User not authorized, cancelling user creation")
				}
			}
		} else {
			log.Print("PosixHostUserAuthorize not implemented, cannot add user.")
			return fmt.Errorf("PosixHostUserAuthorize not implemented, cannot add user")
		}
	}
	userAddCmd := "useradd"
	userID, userIDClaimErr := posixCert.GetUIDClaim()
	if userIDClaimErr != nil {
		log.Print("Cert's GetUIDClaim returned error, will let the system assign random UID for account")
	} else {
		userAddCmd = userAddCmd + fmt.Sprintf(" -u %d", userID)
	}
	primaryGroup, primaryGIDClaimErr := posixCert.GetPrimaryGroupClaim()
	if primaryGIDClaimErr != nil {
		log.Print("Cert's GetPrimaryGroupClaim returned error, will let the system assign random primary GID for account")
	} else {
		if createGroupIfNotExistsImpl, ok := host.(PosixHostCreateGroupIfNotExists); ok {
			createGroupIfNotExistsErr := createGroupIfNotExistsImpl.PosixHostCreateGroupIfNotExists(primaryGroup)
			if createGroupIfNotExistsErr != nil {
				log.Print("CreateGroupIfNotExists returned error creating primary GID, Aborting User Addition")
				return fmt.Errorf("Aborted user addition, errored while creating primary gid for user - %+v", createGroupIfNotExistsErr)
			}
		} else {
			log.Print("PosixHostCreateGroupIfNotExists is not implemented, aborting user addition")
			return fmt.Errorf("PosixHostCreateGroupIfNotExists is not implemented, aborting user addition")
		}
		userAddCmd = userAddCmd + fmt.Sprintf(" -g %d", *primaryGroup.GetGroupID())
	}
	var passwdHash string
	if userAddCmdOptions.DefaultPasswdHash != nil {
		passwdHash = *userAddCmdOptions.DefaultPasswdHash
	}
	if passwdHashImpl, ok := cert.(sshcert.GetLatestPasswdHash); ok {
		var passwdHashErr error
		passwdHash, passwdHashErr = passwdHashImpl.GetLatestPasswdHash()
		if passwdHashErr != nil {
			log.Print("Cert's GetLatestPasswdHash returned error, will create account without a password set")
		}
	}
	if passwdHash != "" {
		userAddCmd = userAddCmd + fmt.Sprintf(" -p %s", passwdHash)
	}
	if userAddCmdOptions.CreateHome && userAddCmdOptions.BaseHomeDir != "" {
		userAddCmd = userAddCmd + fmt.Sprintf(" -m -d %s", strings.TrimSuffix(userAddCmdOptions.BaseHomeDir, "/")+"/"+userLogin)
	}
	if userAddCmdOptions.ExpireDate != nil {
		expiry := userAddCmdOptions.ExpireDate.Format("2006-01-02")
		userAddCmd = userAddCmd + fmt.Sprintf(" -e %s", expiry)
	}
	if userAddCmdOptions.LoginShell != "" {
		userAddCmd = userAddCmd + fmt.Sprintf(" -s %s", userAddCmdOptions.LoginShell)
	}
	if userAddCmdOptions.SystemAccount {
		userAddCmd = userAddCmd + fmt.Sprint(" -r")
	}
	userAddCmd = userAddCmd + fmt.Sprintf(" %s", userLogin)
	if osExecImpl, ok := host.(PosixHostOSExec); ok {
		log.Printf("Executing useradd command %s", userAddCmd)
		_, err := osExecImpl.PosixHostOSExec(nil, "sh", "-c", userAddCmd)
		if err != nil {
			log.Printf("userAdd command %s failed - %+v", userAddCmd, err)
			return err
		}
		return nil
	} else {
		log.Print("PosixHostOSExec not implemented, cannot execute userAddCmd on host. Giving up")
		return fmt.Errorf("PosixHostOSExec not implemented, cannot execute userAddCmd on host. Giving up")
	}
}

func DefaultPosixHostAddMissingGroupsFromCert(principal string, cert sshcert.Cert, host PosixHost, groupAddCmdOptions *DefaultPosixAddGroupOptions) error {
	if getGroupsImpl, ok := cert.(sshcert.GetPosixGroupsClaim); ok {
		groups, groupsClaimErr := getGroupsImpl.GetGroupsClaim()
		if groupsClaimErr != nil {
			log.Print("GetGroupsClaim implementation returned error, aborting missing groups addition")
			return fmt.Errorf("GetGroupsClaim implementation returned error, aborting missing groups addition")
		}
		createGroupIfNotExistsImpl, ok := host.(PosixHostCreateGroupIfNotExists)
		posixHostOSExecImpl, yes := host.(PosixHostOSExec)
		if ok && yes {
			for _, grp := range groups {
				if posixGroupImpl, ok := grp.(group.PosixGroup); ok {
					err := createGroupIfNotExistsImpl.PosixHostCreateGroupIfNotExists(posixGroupImpl)
					if err != nil {
						log.Printf("Errored out checking if exists/adding group %d. Aborting missing groups addition here", posixGroupImpl.GetGroupID())
						return fmt.Errorf("Errored out checking if exists/adding group %d", posixGroupImpl.GetGroupID())
					} else {
						gid := posixGroupImpl.GetGroupID()
						gName := posixGroupImpl.GetGroupName()
						log.Printf("Group %d already exists or was successfully added", *gid)
						err := DefaultPosixHostAssociateUserToSecondaryGroup(principal, *gName, posixHostOSExecImpl)
						if err != nil {
							log.Printf("Failed to associate user %s with secondary group %s", principal, *gName)
							return fmt.Errorf("Errored out associate user %s with secondary group %s", principal, *gName)
						}
					}
				} else {
					log.Printf("Group %+v returned by GetGroupsClaim does not implement the PosixGroup interface. Cannot adding missing group, aborting", grp)
					return fmt.Errorf("Group %+v returned by GetGroupsClaim do not implement the PosixGroup interface. Cannot adding missing group, aborting", grp)
				}
			}
			log.Print("All missing groups were successfully added to the system")
			return nil
		} else {
			log.Print("PosixHostCreateGroupIfNotExists or PosixHostOSExec is not implemented, aborting missing groups addition")
			return fmt.Errorf("PosixHostCreateGroupIfNotExists or PosixHostOSExec is not implemented, aborting missing groups addition")
		}
	} else {
		log.Print("GetGroupsClaim is not implemented on the certificate. No groups added")
		return nil
	}
}

func DefaultPosixHostUserAuthorize(user string, cert sshcert.CertPosixAccount, host PosixHost) (bool, error) {
	if hostOwnershipEntitlementsImpl, ok := host.(PosixHostOwnershipEntitlements); ok {
		ownershipEntitlements := hostOwnershipEntitlementsImpl.PosixHostOwnershipEntitlements()
		userPrimaryGroup, err := cert.GetPrimaryGroupClaim()
		if err != nil {
			log.Printf("GetPrimaryGroupClaim is not implemented by the cert. Cannot authorize user %s", user)
			return false, fmt.Errorf("GetPrimaryGroupClaim is not implemented by the cert")
		}
		userGroupList := make([]string, 0)
		userGroupList = append(userGroupList, *userPrimaryGroup.GetGroupName())
		if groupsClaimImpl, ok := cert.(sshcert.GetPosixGroupsClaim); ok {
			userSecondaryGroups, err := groupsClaimImpl.GetGroupsClaim()
			if err == nil {
				for _, each := range userSecondaryGroups {
					posixGroupImpl, ok := each.(group.PosixGroup)
					if ok {
						grpName := posixGroupImpl.GetGroupName()
						userGroupList = append(userGroupList, *grpName)
					}
				}
			}
		}
		if intersectionAmongStringLists(ownershipEntitlements, userGroupList) {
			log.Printf("Match found between host's entitlements %+v and groups %+v presented in cert for user %s", ownershipEntitlements, userGroupList, user)
			return true, nil
		} else {
			log.Printf("None of host's entitlements %+v matched any groups %+v presented in cert for user %s", ownershipEntitlements, userGroupList, user)
			return false, nil
		}
	} else {
		log.Print("PosixHostOwnershipEntitlements is not implemented. Cannot proceed with authorization")
		return false, fmt.Errorf("PosixHostOwnershipEntitlements is not implemeted. Cannot proceed with authorization")
	}
}

func DefaultPosixHostResetPasswd(user string, passwdHash string, host PosixHost) error {
	//Invoke the resetpwd functionality
	chPasswdStdInput := []byte(user + ":" + passwdHash)
	chPasswdCmd := "chpasswd -e"
	if osExecImpl, ok := host.(PosixHostOSExec); ok {
		_, err := osExecImpl.PosixHostOSExec(chPasswdStdInput, "sh", "-c", chPasswdCmd)
		if err != nil {
			log.Printf("Reset Password command failed - %+v", err)
			return err
		}
		return nil
	} else {
		log.Print("PosixHostOSExec not implemented, cannot execute resetPasswd on host. Giving up")
		return fmt.Errorf("PosixHostOSExec not implemented, cannot execute resetPasswd on host. Giving up")
	}
}

func DefaultPosixHostCreateGroupIfNotExists(group group.PosixGroup, host PosixHost,
	groupAddCmdOptions *DefaultPosixAddGroupOptions, usrgrpsLookup UsrsGrpsLookUp) error {

	grpName := *group.GetGroupName()
	matchedGID, GIDNotExists := usrgrpsLookup.LookupGroupId(strconv.FormatUint(uint64(*group.GetGroupID()), 10))
	if GIDNotExists == nil {
		if matchedGID.Name == grpName {
			return nil
		} else {
			log.Printf("A match for Group ID found but its name does not match %s", *group.GetGroupName())
			return fmt.Errorf("A match for Group ID found but its name does not match %s", *group.GetGroupName())
		}
	}
	if _, groupNameNotExists := usrgrpsLookup.LookupGroup(grpName); groupNameNotExists == nil {
		log.Printf("A match for group name found but its GID does not match %d", group.GetGroupID())
		return fmt.Errorf("A match for group name found but its GID does not match %d", group.GetGroupID())
	}
	groupAddCmd := "groupadd"
	if groupAddCmdOptions.ForceOption {
		groupAddCmd = groupAddCmd + fmt.Sprint(" -f")
	}
	groupAddCmd = groupAddCmd + fmt.Sprintf(" -g %s", strconv.FormatUint(uint64(*group.GetGroupID()), 10))
	if groupAddCmdOptions.NonUniqueGID {
		groupAddCmd = groupAddCmd + fmt.Sprint(" -o")
	}
	if groupAddCmdOptions.PasswdHash != "" {
		groupAddCmd = groupAddCmd + fmt.Sprintf(" -p %s", groupAddCmdOptions.PasswdHash)
	}
	if groupAddCmdOptions.SystemGroup {
		groupAddCmd = groupAddCmd + fmt.Sprint(" -r")
	}
	if groupAddCmdOptions.ChrootDir != "" {
		groupAddCmd = groupAddCmd + fmt.Sprintf(" -R %s", groupAddCmdOptions.ChrootDir)
	}
	groupAddCmd = groupAddCmd + fmt.Sprintf(" %s", grpName)
	if osExecImpl, ok := host.(PosixHostOSExec); ok {
		log.Printf("Executing groupadd command %s", groupAddCmd)
		_, err := osExecImpl.PosixHostOSExec(nil, "sh", "-c", groupAddCmd)
		if err != nil {
			log.Printf("groupAdd command failed - %+v", err)
			return err
		}
		return nil
	} else {
		log.Print("PosixHostOSExec not implemented, cannot execute groupCmdAdd on host. Giving up")
		return fmt.Errorf("PosixHostOSExec not implemented, cannot execute groupCmdAdd on host. Giving up")
	}
}

func DefaultPosixHostOwnershipEntitlements(host PosixHost, envLookup OSEnvLookUp, ec2TagFetcherForKey Ec2TagFetcherMatchingKey) []string {
	//get key
	var key string
	if hostOwnershipEntitlementsKeyImpl, ok := host.(PosixHostOwnershipEntitlementsKey); ok {
		key = hostOwnershipEntitlementsKeyImpl.PosixHostOwnershipEntitlementsKey()
	} else {
		log.Print("PosixHostOwnershipEntitlementsKey implementation is missing, returning empty list")
		return nil
	}
	if key == "" {
		return nil
	}
	result := make([]string, 0)
	//try environment variables
	enVal, ok := envLookup.LookupEnv(key)
	if ok {
		log.Printf("Environment var lookup for entitlement key %s yielded - %s", key, enVal)
		result = append(result, strings.Split(enVal, ":")...)
	} else {
		log.Printf("Environment var lookup for entitlement key %s yielded nil result", key)
	}
	//try ec2 IMDS
	if ec2TagFetcherForKey != nil {
		awsSession := session.Must(session.NewSession())
		ec2metadataClient := ec2metadata.New(awsSession)
		if !ec2metadataClient.Available() {
			log.Print("EC2 Metadata service is not available for the host")
		} else {
			region, err := ec2metadataClient.Region()
			if err != nil {
				log.Print("EC2 Metadata service can't figure out which region the host is running in")
			} else {
				ec2Svc := ec2.New(awsSession, &aws.Config{
					Region: aws.String(region),
				})
				value, err := ec2TagFetcherForKey.FetchEC2TagValueMatchingKey(key, ec2metadataClient, ec2Svc)
				if err != nil {
					log.Print("EC2 tags fetch failed. Returning the list so far")
				} else if value != "" {
					tags := strings.Split(value, ",")
					for _, tag := range tags {
						result = append(result, strings.TrimSpace(tag))
					}
				}
			}
		}
	}
	log.Printf("Entitlements found for key %s on host %+v", key, result)
	return result
}

func DefaultPosixHostOSExec(host PosixHost, exec OSExec, stdInput []byte, cmdAndArgs ...string) (string, error) {
	cmd := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...)
	if stdInput != nil {
		stdIn, stdInerr := cmd.StdinPipe()
		if stdInerr != nil {
			log.Print("Could not get hold of standard input for the command")
			return "", stdInerr
		}
		_, writeErr := stdIn.Write(stdInput)
		if writeErr != nil {
			log.Print("Could not write to the standard input of the command")
			return "", writeErr
		}
		closeErr := stdIn.Close()
		if closeErr != nil {
			log.Print("Could not close standard input pipe of the command")
			return "", closeErr
		}
	}
	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	runErr := cmd.Run()
	if runErr != nil {
		log.Printf("Command run failed due to the error - %+v", runErr)
		return "", fmt.Errorf("Command run failed due to the error - %+v", runErr)
	}
	if stdErr.String() != "" {
		log.Printf("Command run resulted in a standard error - %+v", stdErr.String())
		return "", fmt.Errorf("%s", stdErr.String())
	}
	return stdOut.String(), nil
}

func DefaultFetchEC2TagValueMatchingKey(key string, metadataClient EC2MetadataClient, ec2Service ec2iface.EC2API) (string, error) {
	if !metadataClient.Available() {
		log.Print("EC2 Metadata service is not available for the host")
		return "", fmt.Errorf("EC2 Metadata service is not available for the host")
	}
	instaceID, err := metadataClient.GetMetadata("instance-id")
	if err != nil {
		log.Printf("Errored out getting instance ID from metadata service - %+v", err)
		return "", fmt.Errorf("Errored out getting instance ID from metadata service - %+v", err)
	}
	//svc := ec2.New(awsSession)
	input := &ec2.DescribeTagsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("resource-id"),
				Values: []*string{
					aws.String(instaceID),
				},
			},
		},
	}
	tagDescriptions := make([]*ec2.TagDescription, 0)
	for {
		tagsDataPaginated, err := ec2Service.DescribeTags(input)
		if err != nil {
			log.Printf("Errored out fetching tags for the ec2 instance - %+v", err)
			return "", fmt.Errorf("Errored out fetching tags for the ec2 instance")
		}
		tagDescriptions = append(tagDescriptions, tagsDataPaginated.Tags...)
		if tagsDataPaginated.NextToken != nil {
			input.SetNextToken(*tagsDataPaginated.NextToken)
		} else {
			break
		}
	}
	for _, v := range tagDescriptions {
		if *v.Key == key {
			return *v.Value, nil
		}
	}
	log.Print("No matching key found among ec2 instance tags")
	return "", nil
}

func DefaultPosixHostAssociateUserToSecondaryGroup(user string, group string, host PosixHostOSExec) error {
	userModCmd := fmt.Sprintf("usermod -a -G %s %s", group, user)
	_, err := host.PosixHostOSExec(nil, "sh", "-c", userModCmd)
	if err != nil {
		log.Printf("Group association of user %s to group %s failed - %+v", user, group, err)
		return err
	}
	return nil
}
