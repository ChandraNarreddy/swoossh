package sshcert

import (
	"reflect"
	"testing"
	"time"

	group "github.com/ChandraNarreddy/swoossh/group"
	"golang.org/x/crypto/ssh"
)

var testUserCertType = `ecdsa-sha2-nistp256-cert-v01@openssh.com`
var testUserCert = `AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgGZb9cj6hauyy3vyrxa0b7KY7pxVr3493N9kd7lOnSQAAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/kAAAAAAAAAMwAAAAEAAAAIbmV3X3VzZXIAAAAMAAAACG5ld191c2VyAAAAAGH1evEAAAAAYfwScQAAAAAAAAISAAAAF3Bhc3N3ZF9oYXNoQHN3b29zc2guY29tAAAAfgAAAHoiJDYkcm91bmRzPTY1NjAwMCQ4N1EuaXdDLmcyNlpSSHdzJGpNaDNsZ1czQm8yYUtkMVNuR2xCeng2TTJNbmxYRVBrcnJLUlNwTkRydE5OZTE3SlhGdm1lWGUyZFhUQnEwcUhDTmM5OUVtRi9uZGZCWmZPOGVXZ0gxIgAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAZcHJpbWFyeV9ncm91cEBzd29vc3NoLmNvbQAAACUAAAAhW3siZ2lkIjoxMjIwOSwibmFtZSI6Im5ld191c2VyIn1dAAAAHHNlY29uZGFyeV9ncm91cHNAc3dvb3NzaC5jb20AAABCAAAAPlt7ImdpZCI6MTIwNDAsIm5hbWUiOiJjYXBlbSJ9LHsiZ2lkIjoyMDA5MSwibmFtZSI6ImRlc2lnbmVyIn1dAAAAF3N1ZG9fY2xhaW1zQHN3b29zc2guY29tAAAACAAAAARudWxsAAAAD3VpZEBzd29vc3NoLmNvbQAAAAkAAAAFMTIyMDkAAAAAAAAAaAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSYo0qC/S2EJa8VrRFkbhurCvqX5rhCh+xrTFiMgv/Xz3UiUf/j1UnOvyk3x7xp//Xb8lTjBQenoI1AC+gZzU3jAAAAZQAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAASgAAACEA7TxqXhqGoQXTzXxnHTldmA/ZbMULS6mHm6dUtzoMGt8AAAAhAJ7XOkDBo54+2FxnoTiVvOgMszDsdkzleCHdPk3C6vIs`
var testPubKey = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLUKOM97qxzTfvkO4AqlTzjKEVfipYyu9+vd+6GDjKhOwrsby1zmvI7sj9rMoG6jkgJOFKpCRuc+rOn2iNyWw/k=`

func strUint16(c uint16) *uint16 {
	return &c
}

func strPtr(c string) *string {
	return &c
}

func TestNewDefaultCertPosixAccount(t *testing.T) {
	defPosCert, err := NewDefaultCertPosixAccount(testUserCertType, testUserCert,
		DefaultUserCertExtUIDKey, DefaultUserCertExtPrimaryGroupKey, DefaultUserCertExtSecondaryGroupsKey,
		DefaultUserCertExtSudoClaimsKey, DefaultUserCertExtLatestPasswdHashKey)
	if err != nil {
		t.Errorf("NewDefaultCertPosixAccount returned error for valid cert and type")
	}
	pName, _ := defPosCert.GetPrincipalName()
	if pName != "new_user" {
		t.Errorf("principal name returned is not expected")
	}
	uid, err := defPosCert.GetUIDClaim()
	if err != nil {
		t.Errorf("Get UID claim returned error for DefaultCertPosixAccount")
	}
	if uid != uint32(12209) {
		t.Errorf("uid returned is not expected")
	}
	priGrp, err := defPosCert.GetPrimaryGroupClaim()
	if err != nil {
		t.Errorf("Get primary group claim returned error for DefaultCertPosixAccount")
	}
	if *priGrp.GetGroupName() != "new_user" {
		t.Errorf("primary group name returned is not expected")
	}
	if *priGrp.GetGroupID() != uint16(12209) {
		t.Errorf("primary group id returned is not expected")
	}
	grps, err := defPosCert.GetGroupsClaim()
	if err != nil {
		t.Errorf("Get secondary groups claim returned error for DefaultCertPosixAccount")
	}
	if len(grps) != 2 {
		t.Errorf("Length of secondary groups returned not expected")
	}
	for _, v := range grps {
		if *v.GetGroupName() != "capem" && *v.GetGroupName() != "designer" {
			t.Errorf("sec group names returned are not expected")
		}
		if *v.GetGroupID() != uint16(12040) && *v.GetGroupID() != uint16(20091) {
			t.Errorf("sec group ids returned are not expected")
		}
	}
	passwdHash, err := defPosCert.GetLatestPasswdHash()
	if err != nil {
		t.Errorf("Get latest password hash claim returned error for DefaultCertPosixAccount")
	}
	if passwdHash != "$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1" {
		t.Errorf("passwd hash returned is not expected")
	}
	sudoClaims, err := defPosCert.GetSUDOClaims()
	if err != nil {
		t.Errorf("Get Sudo claims returned error for DefaultCertPosixAccount")
	}
	if sudoClaims != nil {
		t.Errorf("sudo claims returned are not expected")
	}
}

func TestDefaultCertPosixAccountSet(t *testing.T) {
	testPosixCert := &DefaultCertPosixAccount{
		Cert:                &ssh.Certificate{},
		UIDKey:              DefaultUserCertExtUIDKey,
		PrimaryGroupKey:     DefaultUserCertExtPrimaryGroupKey,
		SecondaryGroupsKey:  DefaultUserCertExtSecondaryGroupsKey,
		SudoClaimsKey:       DefaultUserCertExtSudoClaimsKey,
		LatestPasswdHashKey: DefaultUserCertExtLatestPasswdHashKey,
	}
	pubKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(testPubKey))
	testPosixCert.Cert.Key = pubKey

	setPrincipalErr := testPosixCert.SetPrincipalName("new_user")
	if setPrincipalErr != nil {
		t.Errorf("SetPrinicipalName returned error")
	}

	setUIDErr := testPosixCert.SetUIDClaim(uint32(12209))
	if setUIDErr != nil {
		t.Errorf("SetUIDClaim returned error")
	}

	priGrp := &group.DefaultPosixGroup{
		Gid:  strUint16(12209),
		Name: strPtr("new_user"),
	}
	setPrimaryGrpErr := testPosixCert.SetPrimaryGroupClaim(priGrp)
	if setPrimaryGrpErr != nil {
		t.Errorf("SetPrimaryGroupClaim returned error")
	}

	secGrps := []group.PosixGroup{}
	secGrps = append(secGrps, &group.DefaultPosixGroup{
		Gid:  strUint16(12040),
		Name: strPtr("capem"),
	})
	secGrps = append(secGrps, &group.DefaultPosixGroup{
		Gid:  strUint16(20091),
		Name: strPtr("designer"),
	})
	setSecGrpsErr := testPosixCert.SetGroupsClaim(secGrps)
	if setSecGrpsErr != nil {
		t.Errorf("SetGroupsClaim returned error")
	}

	setPasswdHashErr := testPosixCert.SetLatestPasswdHash("$6$rounds=656000$87Q.iwC.g26ZRHws$jMh3lgW3Bo2aKd1SnGlBzx6M2MnlXEPkrrKRSpNDrtNNe17JXFvmeXe2dXTBq0qHCNc99EmF/ndfBZfO8eWgH1")
	if setPasswdHashErr != nil {
		t.Errorf("SetLatestPasswdHash returned error")
	}

	setSudoClaimsErr := testPosixCert.SetSUDOClaims(nil)
	if setSudoClaimsErr != nil {
		t.Errorf("SetSUDOClaims returned error")
	}

	testPosixCert.Cert.ValidAfter = uint64(time.Now().Unix())
	testPosixCert.Cert.ValidBefore = uint64(time.Now().Unix()) + 600
	testPosixCert.Cert.Extensions["permit-agent-forwarding"] = ""
	testPosixCert.Cert.Extensions["permit-X11-forwarding"] = ""
	testPosixCert.Cert.Extensions["permit-port-forwarding"] = ""
	testPosixCert.Cert.Extensions["permit-pty"] = ""
	testPosixCert.Cert.Extensions["permit-user-rc"] = ""
	testPosixCert.Cert.CriticalOptions = map[string]string{}

	p, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(testUserCertType + " " + testUserCert))
	pKey, _ := ssh.ParsePublicKey(p.Marshal())
	validateCert, _ := pKey.(*ssh.Certificate)
	if !reflect.DeepEqual(testPosixCert.Cert.Key, validateCert.Key) {
		t.Errorf("Key value set in test cert does not match up to expectation")
	}
	if !reflect.DeepEqual(testPosixCert.Cert.Permissions.CriticalOptions, validateCert.Permissions.CriticalOptions) {
		t.Errorf("Critical options set in test cert do not match up to expectation")
	}
	if !reflect.DeepEqual(testPosixCert.Cert.ValidPrincipals, validateCert.ValidPrincipals) {
		t.Errorf("Valid Principals set in test cert do not match up to expectation")
	}
	if !reflect.DeepEqual(testPosixCert.Cert.Permissions.Extensions, validateCert.Permissions.Extensions) {
		t.Errorf("Extensions set in test cert do not match up to expectation")
	}
}

func TestDefaultCertPosixAccountGetGroupsClaim(t *testing.T) {
	//DefaultCertPosixAccountGetGroupsClaim(cert *ssh.Certificate, secondaryGroupsKey string) ([]*group.DefaultPosixGroup, error)
	certPem := `ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgTyMpNdxpOjoHgH6TcYvEVOFn2CZ2sWqFJ5iE4qCWupMAAAAIbmlzdHAyNTYAAABBBHbDtrblMnQa9ZgrR2ESeghVW/1pFRWGm54Jmt1N+KTqveQ/hVnQ7TGNeHq4Y3MuWiuAgKyQww0BWfuA8iQKNtoAAAAAAAAABQAAAAEAAAAIbmV3X3VzZXIAAAAMAAAACG5ld191c2VyAAAAAGH/230AAAAAYgZy/QAAAAAAAAISAAAAF3Bhc3N3ZF9oYXNoQHN3b29zc2guY29tAAAAfgAAAHoiJDYkcm91bmRzPTY1NjAwMCQ4N1EuaXdDLmcyNlpSSHdzJGpNaDNsZ1czQm8yYUtkMVNuR2xCeng2TTJNbmxYRVBrcnJLUlNwTkRydE5OZTE3SlhGdm1lWGUyZFhUQnEwcUhDTmM5OUVtRi9uZGZCWmZPOGVXZ0gxIgAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAZcHJpbWFyeV9ncm91cEBzd29vc3NoLmNvbQAAACUAAAAhW3siZ2lkIjoxMjIwOSwibmFtZSI6Im5ld191c2VyIn1dAAAAHHNlY29uZGFyeV9ncm91cHNAc3dvb3NzaC5jb20AAABCAAAAPlt7ImdpZCI6MTIwNDAsIm5hbWUiOiJjYXBlbSJ9LHsiZ2lkIjoyMDA5MSwibmFtZSI6ImRlc2lnbmVyIn1dAAAAF3N1ZG9fY2xhaW1zQHN3b29zc2guY29tAAAACAAAAARudWxsAAAAD3VpZEBzd29vc3NoLmNvbQAAAAkAAAAFMTIyMDkAAAAAAAAAaAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSYo0qC/S2EJa8VrRFkbhurCvqX5rhCh+xrTFiMgv/Xz3UiUf/j1UnOvyk3x7xp//Xb8lTjBQenoI1AC+gZzU3jAAAAZAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAASQAAACAOqWEXzjN09q4KF32Z+1jCN5vsD8Zd46miQnsWLujqmwAAACEAk7WbMI2xWlUx3F8V06KKjgcq+/0MacB9AKKfpsNskw8=`
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(certPem))
	pubKey, _ := ssh.ParsePublicKey(pub.Marshal())
	cert, _ := pubKey.(*ssh.Certificate)
	grps, grpsClaimErr := DefaultCertPosixAccountGetGroupsClaim(cert, DefaultUserCertExtSecondaryGroupsKey)
	if grpsClaimErr != nil {
		t.Errorf("DefaultCertPosixAccountGetGroupsClaim errored out - %+v", grpsClaimErr)
	}
	if *grps[0].Gid != uint16(12040) {
		t.Errorf("Gid %d of 1st group returned by DefaultCertPosixAccountGetGroupsClaim is not expected %d", *grps[0].Gid, 12040)
	}
	if *grps[1].Gid != uint16(20091) {
		t.Errorf("Gid %d of 1st group returned by DefaultCertPosixAccountGetGroupsClaim is not expected %d", *grps[1].Gid, 20091)
	}
	if *grps[0].Name != "capem" {
		t.Errorf("Grp Name %s of 1st group returned by DefaultCertPosixAccountGetGroupsClaim is not expected %s", *grps[0].Name, "capem")
	}
	if *grps[1].Name != "designer" {
		t.Errorf("Grp Name %s of 1st group returned by DefaultCertPosixAccountGetGroupsClaim is not expected %s", *grps[1].Name, "designer")
	}
}
