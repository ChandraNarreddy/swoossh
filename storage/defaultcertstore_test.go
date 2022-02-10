package storage

import (
	"testing"
	"time"

	"github.com/ChandraNarreddy/swoossh/ca"
	"github.com/ChandraNarreddy/swoossh/group"
	"github.com/ChandraNarreddy/swoossh/sshcert"
	"github.com/ChandraNarreddy/swoossh/user"
	"golang.org/x/crypto/ssh"
)

func TestGetCertSearchResults(t *testing.T) {

}

func TestDefaultDynamoDBStoreGetSSHCertsForUser(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client

	//put user first
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
	//putting certs now
	for i := 0; i <= 4; i++ {
		time.Sleep(time.Second) // allowing for ddb to populate the record as a new one
		posixCert := &sshcert.DefaultCertPosixAccount{
			Cert:                &ssh.Certificate{},
			UIDKey:              sshcert.DefaultUserCertExtUIDKey,
			PrimaryGroupKey:     sshcert.DefaultUserCertExtPrimaryGroupKey,
			SecondaryGroupsKey:  sshcert.DefaultUserCertExtSecondaryGroupsKey,
			SudoClaimsKey:       sshcert.DefaultUserCertExtSudoClaimsKey,
			LatestPasswdHashKey: sshcert.DefaultUserCertExtLatestPasswdHashKey,
		}
		pubKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n"))
		posixCert.Cert.Key = pubKey
		posixCert.Cert.ValidAfter = uint64(time.Now().Unix())
		posixCert.Cert.ValidBefore = uint64(time.Now().Unix()) + ca.DefaultCertValidityPeriodInSeconds
		posixCert.Cert.Extensions = map[string]string{}
		posixCert.Cert.Extensions["permit-agent-forwarding"] = ""
		posixCert.Cert.Extensions["permit-X11-forwarding"] = ""
		posixCert.Cert.Extensions["permit-port-forwarding"] = ""
		posixCert.Cert.Extensions["permit-pty"] = ""
		posixCert.Cert.Extensions["permit-user-rc"] = ""

		csr := &ca.DefaultCSR{
			PublicKey:       &posixCert.Cert.Key,
			Principals:      posixCert.Cert.ValidPrincipals,
			CertType:        ssh.UserCert,
			CertExtensions:  posixCert.Cert.Extensions,
			CriticalOptions: map[string]string{},
			ValidAfter:      &posixCert.Cert.ValidAfter,
			ValidBefore:     &posixCert.Cert.ValidBefore,
		}
		keyPEM := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS1CjjPe6sc0375DuAKpU84yhFX4qWM
rvfr3fuhg4yoTsK7G8tc5ryO7I/azKBuo5ICThSqQkbnPqzp9ojclsP5AAAAwEzr071M69
O9AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO
4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/
kAAAAgXT6Abfcw/mi4sNJPudZzHnHZyCvvrGFkeTnSK9F9ZkMAAAAjY2hhbmRyYWthbnRo
cmVkZHlATWFjQm9vay1Qcm8ubG9jYWwBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`

		hostSigner, err := ssh.ParsePrivateKey([]byte(keyPEM))
		if err != nil {
			t.Errorf("Could not create host signer - %+v", err)
		}
		userSigner, err := ssh.ParsePrivateKey([]byte(keyPEM))
		if err != nil {
			t.Errorf("Could not create user cert signer - %+v", err)
		}
		defaultCA := &ca.DefaultCA{
			HostSigner:           hostSigner,
			UserSigner:           userSigner,
			RefreshSigners:       func(c *ca.DefaultCA) error { return nil },
			HostCertsMaxValidity: uint64(5),
			UserCertsMaxValidity: uint64(5),
		}
		signedCert, signErr := defaultCA.SignCert(csr)
		if signErr != nil {
			t.Errorf("Error occurred while signing CSR - %+v", signErr)
		}
		putCertErr := ddbStore.PutSSHCertForUser(signedCert, usr)
		if putCertErr != nil {
			t.Errorf("Error occurred while adding certificates  on user's account- %+v", putCertErr)
		}
	}

	//now searching for certs
	filter1 := &DefaultStoreSSHCertSearchFilter{
		UserFilter: &DefaultStoreUserFilter{
			PricipalNameProjection: strPtr("smith"),
		},
		PageSize: intPtr(10),
		Order:    &forw,
	}
	resp1, err1 := DefaultDynamoDBStoreGetSSHCertsForUser(filter1, ddbStore)
	if err1 != nil {
		t.Errorf("Get certs for user errored out - %+v", err1)
	}
	if len(resp1.GetCertSearchResults()) != 5 {
		t.Errorf("Get certs for user returned %d records than expected 5", len(resp1.GetCertSearchResults()))
	}

	filter2 := &DefaultStoreSSHCertSearchFilter{
		UserFilter: &DefaultStoreUserFilter{
			PricipalNameProjection: strPtr("smith"),
		},
		PageSize: intPtr(3),
		Order:    &forw,
	}
	resp2, err2 := DefaultDynamoDBStoreGetSSHCertsForUser(filter2, ddbStore)
	if err2 != nil {
		t.Errorf("Get certs for user errored out - %+v", err2)
	}
	if len(resp2.GetCertSearchResults()) != 3 {
		t.Errorf("Get certs for user returned %d records than expected 3", len(resp2.GetCertSearchResults()))
	}

	defSSHCertResp, ok := resp2.(*DefaultStoreSSHCertSearchResponse)
	if !ok {
		t.Error("Get certs response is not DefaultStoreSSHCertSearchResponse")
	}

	filter3 := &DefaultStoreSSHCertSearchFilter{
		UserFilter: &DefaultStoreUserFilter{
			PricipalNameProjection: strPtr("smith"),
		},
		PageSize:  intPtr(2),
		Order:     &rev,
		PageToken: defSSHCertResp.NextPageToken,
	}
	resp3, err3 := DefaultDynamoDBStoreGetSSHCertsForUser(filter3, ddbStore)
	if err3 != nil {
		t.Errorf("Get certs for user errored out - %+v", err3)
	}
	if len(resp3.GetCertSearchResults()) != 2 {
		t.Errorf("Get certs for user returned %d records than expected 2", len(resp3.GetCertSearchResults()))
	}

}

func TestDefaultDynamoDBStorePutSSHCertForUser(t *testing.T) {
	if e := cleanUpDB(); e != nil {
		t.Errorf("Failed to clean up, cannot proceed with create user tests")
		return
	}
	client := localDDBClient()
	ddbStore.DDBClient = client

	//put user first
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
	//putting certs now
	for i := 0; i <= 4; i++ {
		posixCert := &sshcert.DefaultCertPosixAccount{
			Cert:                &ssh.Certificate{},
			UIDKey:              sshcert.DefaultUserCertExtUIDKey,
			PrimaryGroupKey:     sshcert.DefaultUserCertExtPrimaryGroupKey,
			SecondaryGroupsKey:  sshcert.DefaultUserCertExtSecondaryGroupsKey,
			SudoClaimsKey:       sshcert.DefaultUserCertExtSudoClaimsKey,
			LatestPasswdHashKey: sshcert.DefaultUserCertExtLatestPasswdHashKey,
		}
		pubKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=\n"))
		posixCert.Cert.Key = pubKey
		posixCert.Cert.ValidAfter = uint64(time.Now().Unix())
		posixCert.Cert.ValidBefore = uint64(time.Now().Unix()) + ca.DefaultCertValidityPeriodInSeconds
		posixCert.Cert.Extensions = map[string]string{}
		posixCert.Cert.Extensions["permit-agent-forwarding"] = ""
		posixCert.Cert.Extensions["permit-X11-forwarding"] = ""
		posixCert.Cert.Extensions["permit-port-forwarding"] = ""
		posixCert.Cert.Extensions["permit-pty"] = ""
		posixCert.Cert.Extensions["permit-user-rc"] = ""

		csr := &ca.DefaultCSR{
			PublicKey:       &posixCert.Cert.Key,
			Principals:      posixCert.Cert.ValidPrincipals,
			CertType:        ssh.UserCert,
			CertExtensions:  posixCert.Cert.Extensions,
			CriticalOptions: map[string]string{},
			ValidAfter:      &posixCert.Cert.ValidAfter,
			ValidBefore:     &posixCert.Cert.ValidBefore,
		}
		keyPEM := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS1CjjPe6sc0375DuAKpU84yhFX4qWM
rvfr3fuhg4yoTsK7G8tc5ryO7I/azKBuo5ICThSqQkbnPqzp9ojclsP5AAAAwEzr071M69
O9AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO
4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/
kAAAAgXT6Abfcw/mi4sNJPudZzHnHZyCvvrGFkeTnSK9F9ZkMAAAAjY2hhbmRyYWthbnRo
cmVkZHlATWFjQm9vay1Qcm8ubG9jYWwBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`

		hostSigner, _ := ssh.ParsePrivateKey([]byte(keyPEM))
		userSigner, _ := ssh.ParsePrivateKey([]byte(keyPEM))
		defaultCA := &ca.DefaultCA{
			HostSigner:           hostSigner,
			UserSigner:           userSigner,
			RefreshSigners:       func(c *ca.DefaultCA) error { return nil },
			HostCertsMaxValidity: uint64(5),
			UserCertsMaxValidity: uint64(5),
		}
		signedCert, signErr := defaultCA.SignCert(csr)
		if signErr != nil {
			t.Errorf("Error occurred while signing CSR - %+v", signErr)
		}
		putCertErr := ddbStore.PutSSHCertForUser(signedCert, usr)
		if putCertErr != nil {
			t.Errorf("Error occurred while adding certificates  on user's account- %+v", putCertErr)
		}
	}
}
