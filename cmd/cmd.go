package main

// ref
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
// https://man7.org/linux/man-pages/man1/ssh-keygen.1.html
// https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	osuser "os/user"

	ap "github.com/ChandraNarreddy/swoossh/authorizedprincipals"
	"github.com/ChandraNarreddy/swoossh/sshcert"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

type usrGrpLookUp struct{}

func (c *usrGrpLookUp) Lookup(username string) (*osuser.User, error) {
	return osuser.Lookup(username)
}
func (c *usrGrpLookUp) LookupGroupId(gid string) (*osuser.Group, error) {
	return osuser.LookupGroupId(gid)
}
func (c *usrGrpLookUp) LookupGroup(name string) (*osuser.Group, error) {
	return osuser.LookupGroup(name)
}

type osExecPosix struct{}

func (c *osExecPosix) Command(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}

type osEnvLookUp struct{}

func (c *osEnvLookUp) LookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}

type ec2TagFetcherForKey struct{}

func (c *ec2TagFetcherForKey) FetchEC2TagValueMatchingKey(key string, metadataClient ap.EC2MetadataClient, ec2Service ec2iface.EC2API) (string, error) {
	return ap.DefaultFetchEC2TagValueMatchingKey(key, metadataClient, ec2Service)
}

func ptrStr(s string) *string {
	return &s
}

//setup an type alias instead to the DefaultPosixtHost here and implement all the interfaces that are necessary
//If the default implementation suits your requirements, just call them in your implementation.
//If not, please write your own implementation

type defaultPosixtHost struct {
	*ap.DefaultPosixtHost
}

func prepareHost(entitlementsKey string, targetUser string) (defaultPosixtHost, error) {
	//appending well known paths here
	path := os.Getenv("PATH")
	pathAppend := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin:/sbin:/bin"
	path = path + ":" + pathAppend
	os.Setenv("PATH", path)

	defaultPosixAddUserOptions := &ap.DefaultPosixAddUserOptions{
		CreateHome:    true,
		BaseHomeDir:   "/home",
		LoginShell:    "/bin/bash",
		ExpireDate:    nil,
		SystemAccount: false,
	}
	defaultPosixAddGroupOptions := &ap.DefaultPosixAddGroupOptions{
		ForceOption:  false,
		NonUniqueGID: false,
		PasswdHash:   "",
		SystemGroup:  false,
		ChrootDir:    "",
	}

	host := defaultPosixtHost{
		DefaultPosixtHost: &ap.DefaultPosixtHost{
			CreateUserIfNotExistsOption:    true,
			DisableNewAccountAuthorization: false,
			HostOwnershipEntitlementsKey:   entitlementsKey,
			SSHCmdTargetUser:               targetUser,
			ResetPasswdWithLatestFromCert:  true,
			UserAddCmdOptions:              defaultPosixAddUserOptions,
			AddMissingGroupsFromCert:       true,
			GroupAddCmdOptions:             defaultPosixAddGroupOptions,
			OSLookup:                       &usrGrpLookUp{},
			Exec:                           &osExecPosix{},
			EnvLookUp:                      &osEnvLookUp{},
			Ec2TagFetcherForKey:            &ec2TagFetcherForKey{},
		},
	}
	return host, nil
}

//setup an type alias instead to the sshcert.DefaultCertPosixAccount here and implement all the interfaces that are necessary
//If the default implementation suits your requirements, just call them in your implementation.
//If not, please write your own implementation

type defaultCertPosixAccount struct {
	sshcert.DefaultCertPosixAccount
}

func prepareCert(base64Cert, certType, uidKey, primaryGroupKey, secondaryGroupsKey,
	sudoClaimsKey, latestPasswdHashKey string) (defaultCertPosixAccount, error) {

	cert, err := sshcert.UnmarshalCert(certType, base64Cert)
	if err != nil {
		log.Println("Unmarshalling certificate failed")
		return defaultCertPosixAccount{}, err
	}
	if cert.ValidPrincipals == nil || len(cert.ValidPrincipals) == 0 {
		log.Println("Principals field of the certificate is empty")
		return defaultCertPosixAccount{}, fmt.Errorf("Principals field of the certificate is empty")
	}
	defaultCertPosix := defaultCertPosixAccount{
		DefaultCertPosixAccount: sshcert.DefaultCertPosixAccount{
			Cert:                cert,
			UIDKey:              uidKey,
			PrimaryGroupKey:     primaryGroupKey,
			SecondaryGroupsKey:  secondaryGroupsKey,
			SudoClaimsKey:       sudoClaimsKey,
			LatestPasswdHashKey: latestPasswdHashKey,
		},
	}
	return defaultCertPosix, nil
}

func main() {
	var logFile = "/var/log/swoossh_cmd.log"
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening logging file: %v", err)
	}
	defer f.Close()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix("sshauthprincipalscmd")
	log.SetOutput(f)

	//defining command line arguments as flags here
	targetUser := flag.String("targetUser", "", "target user account to log into %u")
	base64Cert := flag.String("cert", "", "base64-encoded certificate %k")
	certType := flag.String("type", "", "certificate type %t")
	entitlementsKey := flag.String("en_key", "", "entitlements key for the host")
	uidKey := flag.String("uid_key", sshcert.DefaultUserCertExtUIDKey, "Key to grab User's UID from cert's extensions field")
	primaryGroupKey := flag.String("group_key", sshcert.DefaultUserCertExtPrimaryGroupKey, "Key to grab User's primary group data from cert's extensions field")
	secondaryGroupsKey := flag.String("sec_groups_key", sshcert.DefaultUserCertExtSecondaryGroupsKey, "Key to grab User's secondary groups data from cert's extensions field")
	sudoClaimsKey := flag.String("sudo_claims_key", sshcert.DefaultUserCertExtSudoClaimsKey, "Key to grab Sudo Rules from cert's extensions field")
	latestPasswdHashKey := flag.String("passwd_hash_key", sshcert.DefaultUserCertExtLatestPasswdHashKey, "Key to grab User's passwd hash from cert's extensions field")
	/*
		CAKeyFingerPrint := flag.String("F", "", "CA Key FingerPrint %F")
		userCertFingerPrint := flag.String("f", "", "User cert FingerPrint %f")
		userHomeDir := flag.String("h", "", "User Home Directory %h")
		keyID := flag.String("i", "", "Key ID in the certificate %i")
		base64CAPubKey := flag.String("K", "", "base64-encoded CA key %K")
		certSerial := flag.String("s", "", "serial number of the certificate %s")
		CAKeyType := flag.String("T", "", "CA Key Type %T")
		userName := flag.String("u", "", "username %u")
	*/
	flag.Parse()

	host, hostPrepErr := prepareHost(*entitlementsKey, *targetUser)
	if hostPrepErr != nil {
		log.Fatal("Fatal! Could not prepare host, Dying!")
	}
	//validating implementation here
	d := defaultPosixtHost{}
	var _ ap.PosixHostResetPasswd = d
	var _ ap.PosixHostUserAuthorize = d
	var _ ap.PosixHostCreateGroupIfNotExists = d
	var _ ap.PosixHostOSExec = d
	var _ ap.PosixHostOwnershipEntitlements = d
	var _ ap.PosixHostOwnershipEntitlementsKey = d
	var _ ap.MatchCertClaimToAnExistingAccount = d
	var _ ap.AddUserToSystem = d
	var _ ap.AddMissingGroups = d
	var _ ap.CreateUserIfNotExists = d
	var _ ap.CreateMissingGroups = d
	var _ ap.PrintAuthorizedPrincipalsFile = d
	//
	cert, certPrepErr := prepareCert(*base64Cert, *certType, *uidKey,
		*primaryGroupKey, *secondaryGroupsKey, *sudoClaimsKey, *latestPasswdHashKey)
	if certPrepErr != nil {
		log.Fatal("Fatal! Could not prepare cert from extracted data, Dying!")
	}

	defaultAuthorizer := &ap.DefaultAuthorizer{
		CertClaims: &cert,
		Host:       host,
	}
	log.Print(defaultAuthorizer.AuthorizeUser())

}
