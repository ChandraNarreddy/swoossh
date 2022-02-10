package sshcert

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	group "github.com/ChandraNarreddy/swoossh/group"
	"golang.org/x/crypto/ssh"
)

var (
	DefaultUserCertExtUIDKey              = "uid@swoossh.com"
	DefaultUserCertExtPrimaryGroupKey     = "primary_group@swoossh.com"
	DefaultUserCertExtSecondaryGroupsKey  = "secondary_groups@swoossh.com"
	DefaultUserCertExtSudoClaimsKey       = "sudo_claims@swoossh.com"
	DefaultUserCertExtLatestPasswdHashKey = "passwd_hash@swoossh.com"
)

type DefaultCertPosixAccount struct {
	Cert                *ssh.Certificate
	UIDKey              string
	PrimaryGroupKey     string
	SecondaryGroupsKey  string
	SudoClaimsKey       string
	LatestPasswdHashKey string
}

func (c *DefaultCertPosixAccount) GetPrincipalName() (string, error) {
	return DefaultCertPosixAccountGetPrincipalName(c.Cert), nil
}

func (c *DefaultCertPosixAccount) SetPrincipalName(principalName string) error {
	return DefaultCertPosixAccountSetPrincipalName(c.Cert, principalName)
}

func (c *DefaultCertPosixAccount) GetUIDClaim() (uint32, error) {
	return DefaultCertPosixAccountGetUIDClaim(c.Cert, c.UIDKey)
}

func (c *DefaultCertPosixAccount) SetUIDClaim(uid uint32) error {
	return DefaultCertPosixAccountSetUIDClaim(c.Cert, uid, c.UIDKey)
}

func (c *DefaultCertPosixAccount) GetPrimaryGroupClaim() (group.PosixGroup, error) {
	return DefaultCertPosixAccountGetPrimaryGroupClaim(c.Cert, c.PrimaryGroupKey)
}

func (c *DefaultCertPosixAccount) SetPrimaryGroupClaim(grp group.PosixGroup) error {
	if defaultPosixGroup, ok := grp.(*group.DefaultPosixGroup); !ok {
		log.Printf("Group passed is not of type DefaultPosixGroup, cannot continue")
		return fmt.Errorf("Group %+v passed is not of type DefaultPosixGroup", grp)
	} else {
		return DefaultCertPosixAccountSetPrimaryGroupClaim(c.Cert, defaultPosixGroup, c.PrimaryGroupKey)
	}
}

func (c *DefaultCertPosixAccount) GetGroupsClaim() ([]group.PosixGroup, error) {
	groupClaims, err := DefaultCertPosixAccountGetGroupsClaim(c.Cert, c.SecondaryGroupsKey)
	if err != nil {
		return nil, err
	}
	result := make([]group.PosixGroup, 0)
	for _, each := range groupClaims {
		result = append(result, each)
	}
	return result, nil
}

func (c *DefaultCertPosixAccount) SetGroupsClaim(secGrps []group.PosixGroup) error {
	defaultPosixSecGrps := make([]*group.DefaultPosixGroup, 0)
	for _, each := range secGrps {
		if secGrp, ok := each.(*group.DefaultPosixGroup); !ok {
			log.Printf("One of the secondary groups %+v is not of type DefaultPosixGroup", each)
			return fmt.Errorf("One of the secondary groups is not of type DefaultPosixGroup")
		} else {
			defaultPosixSecGrps = append(defaultPosixSecGrps, secGrp)
		}
	}
	return DefaultCertPosixAccountSetGroupsClaim(c.Cert, defaultPosixSecGrps, c.SecondaryGroupsKey)
}

func (c *DefaultCertPosixAccount) GetSUDOClaims() ([]string, error) {
	return DefaultCertPosixAccountGetSUDOClaims(c.Cert, c.SudoClaimsKey)
}

func (c *DefaultCertPosixAccount) SetSUDOClaims(sudoClaims []string) error {
	return DefaultCertPosixAccountSetSUDOClaims(c.Cert, sudoClaims, c.SudoClaimsKey)
}

func (c *DefaultCertPosixAccount) GetLatestPasswdHash() (string, error) {
	return DefaultCertPosixAccountGetLatestPasswdHash(c.Cert, c.LatestPasswdHashKey)
}

func (c *DefaultCertPosixAccount) SetLatestPasswdHash(latestPasswdHash string) error {
	return DefaultCertPosixAccountSetLatestPasswdHash(c.Cert, latestPasswdHash, c.LatestPasswdHashKey)
}

func NewDefaultCertPosixAccount(certType, base64Cert, uidKey, primaryGroupKey,
	secondaryGroupsKey, sudoClaimsKey, latestPasswdHashKey string) (DefaultCertPosixAccount, error) {
	cert, err := UnmarshalCert(certType, base64Cert)
	if err != nil {
		log.Println("Unmarshalling certificate failed")
		return DefaultCertPosixAccount{}, err
	}
	if cert.ValidPrincipals == nil || len(cert.ValidPrincipals) == 0 {
		log.Println("Principals field of the certificate is empty")
		return DefaultCertPosixAccount{}, fmt.Errorf("Principals field of the certificate is empty")
	}
	defaultCert := DefaultCertPosixAccount{
		Cert:                cert,
		UIDKey:              uidKey,
		PrimaryGroupKey:     primaryGroupKey,
		SecondaryGroupsKey:  secondaryGroupsKey,
		SudoClaimsKey:       sudoClaimsKey,
		LatestPasswdHashKey: latestPasswdHashKey,
	}
	return defaultCert, nil
}

func DefaultCertPosixAccountGetPrincipalName(cert *ssh.Certificate) string {
	return cert.ValidPrincipals[0]
}

func DefaultCertPosixAccountSetPrincipalName(cert *ssh.Certificate, principalName string) error {
	cert.ValidPrincipals = []string{principalName}
	return nil
}

func DefaultCertPosixAccountGetUIDClaim(cert *ssh.Certificate, uidKey string) (uint32, error) {
	extensions := cert.Extensions
	if uidStr, found := extensions[uidKey]; found {
		uid, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			log.Printf("uid from certificate %s could not be convered to uint", uidStr)
			return 0, fmt.Errorf("Failed to convert uid in certificate to integer")
		}
		return uint32(uid), nil
	}
	log.Print("uidkey not found in certificate's extensions")
	return 0, fmt.Errorf("uidkey not found in certificate's extensions")
}

func DefaultCertPosixAccountSetUIDClaim(cert *ssh.Certificate, uid uint32, uidKey string) error {
	if cert.Extensions == nil {
		cert.Extensions = map[string]string{}
	}
	cert.Extensions[uidKey] = strconv.Itoa(int(uid))
	return nil
}

func DefaultCertPosixAccountGetPrimaryGroupClaim(cert *ssh.Certificate, primaryGroupKey string) (*group.DefaultPosixGroup, error) {
	extensions := cert.Extensions
	if primaryGroupStr, found := extensions[primaryGroupKey]; found {
		if posixGroups, err := decodePosixGroups(primaryGroupStr); err != nil {
			log.Print("Errored out extracting primary Posix Group details from cert")
			return nil, fmt.Errorf("Errored out extracting primary Posix Group details from cert")
		} else {
			return posixGroups[0], nil
		}
	}
	log.Print("primaryGroupKey not found in certificate's extensions")
	return nil, fmt.Errorf("primaryGroupKey not found in certificate's extensions")
}

func DefaultCertPosixAccountSetPrimaryGroupClaim(cert *ssh.Certificate, grp *group.DefaultPosixGroup, primaryGroupKey string) error {
	grps := []group.DefaultPosixGroup{*grp}
	encodedGrps, encodeErr := encodePosixGroups(grps)
	if encodeErr != nil {
		log.Printf("Error while encoding primary group of user - %+v", encodeErr)
		return fmt.Errorf("Error while encoding primary group of user")
	}
	if cert.Extensions == nil {
		cert.Extensions = map[string]string{}
	}
	cert.Extensions[primaryGroupKey] = encodedGrps
	return nil
}

func DefaultCertPosixAccountGetGroupsClaim(cert *ssh.Certificate, secondaryGroupsKey string) ([]*group.DefaultPosixGroup, error) {
	extensions := cert.Extensions
	if secondaryGroupsStr, found := extensions[secondaryGroupsKey]; found {
		if secondaryGroups, err := decodePosixGroups(secondaryGroupsStr); err != nil {
			log.Print("Errored out extracting secondary Posix Groups details from cert")
			return nil, fmt.Errorf("Errored out extracting secondary Posix Groups details from cert")
		} else {
			return secondaryGroups, nil
		}
	}
	log.Print("secondaryGroupsKey not found in certificate's extensions")
	return nil, fmt.Errorf("secondaryGroupsKey not found in certificate's extensions")
}

func DefaultCertPosixAccountSetGroupsClaim(cert *ssh.Certificate, secGrps []*group.DefaultPosixGroup, secondaryGroupsKey string) error {
	grps := make([]group.DefaultPosixGroup, 0)
	for _, each := range secGrps {
		grps = append(grps, *each)
	}
	encodeGrps, encodeErr := encodePosixGroups(grps)
	if encodeErr != nil {
		log.Printf("Error while encoding secondary groups of user - %+v", encodeErr)
		return fmt.Errorf("Error while encoding secondary groups of user")
	}
	if cert.Extensions == nil {
		cert.Extensions = map[string]string{}
	}
	cert.Extensions[secondaryGroupsKey] = encodeGrps
	return nil
}

func DefaultCertPosixAccountGetSUDOClaims(cert *ssh.Certificate, sudoClaimsKey string) ([]string, error) {
	extensions := cert.Extensions
	if sudoClaimsStr, found := extensions[sudoClaimsKey]; found {
		if sudoClaims, err := decodeSudoClaims(sudoClaimsStr); err != nil {
			log.Print("Errored out extracting sudo claims details from cert")
			return nil, fmt.Errorf("Errored out extracting sudo claims details from cert")
		} else {
			return sudoClaims, nil
		}
	}
	log.Print("sudoClaimsKey not found in certificate's extensions")
	return nil, fmt.Errorf("sudoClaimsKey not found in certificate's extensions")
}

func DefaultCertPosixAccountSetSUDOClaims(cert *ssh.Certificate, sudoClaims []string, sudoClaimsKey string) error {
	encodedClaims, encodeErr := encodeSudoClaims(sudoClaims)
	if encodeErr != nil {
		log.Printf("Error while encoding sudo claims of user - %+v", encodeErr)
		return fmt.Errorf("Error while encoding sudo claims of user")
	}
	if cert.Extensions == nil {
		cert.Extensions = map[string]string{}
	}
	cert.Extensions[sudoClaimsKey] = encodedClaims
	return nil
}

func DefaultCertPosixAccountGetLatestPasswdHash(cert *ssh.Certificate, latestPasswdHashKey string) (string, error) {
	extensions := cert.Extensions
	if passwdHashStr, found := extensions[latestPasswdHashKey]; found {
		if passwdHash, err := decodePasswdHash(passwdHashStr); err != nil {
			log.Print("Errored out extracting latestPasswdHash from cert")
			return "", fmt.Errorf("Errored out extracting latestPasswdHash from cert")
		} else {
			return passwdHash, nil
		}
	}
	log.Print("latestPasswdHashKey not found in certificate's extensions")
	return "", fmt.Errorf("latestPasswdHashKey not found in certificate's extensions")
}

func DefaultCertPosixAccountSetLatestPasswdHash(cert *ssh.Certificate, latestPasswdHash string, latestPasswdHashKey string) error {
	encodedPasswdHash, encodeErr := encodePasswdHash(latestPasswdHash)
	if encodeErr != nil {
		log.Printf("Error while encoding password hash of user - %+v", encodeErr)
		return fmt.Errorf("Error while encoding password hash of user")
	}
	if cert.Extensions == nil {
		cert.Extensions = map[string]string{}
	}
	cert.Extensions[latestPasswdHashKey] = encodedPasswdHash
	return nil
}

func encodePosixGroups(groups []group.DefaultPosixGroup) (string, error) {
	jsonGroups, err := json.Marshal(groups)
	if err != nil {
		log.Print("Could not marshall the groups to Json")
		return "", fmt.Errorf("Could not marshall the groups to Json")
	}
	log.Print("Marshalled groups to string")
	return string(jsonGroups), nil
}

func decodePosixGroups(groupString string) ([]*group.DefaultPosixGroup, error) {
	var a []group.DefaultPosixGroup
	err := json.Unmarshal([]byte(groupString), &a)
	if err != nil {
		log.Print("Errored out unmarshalling groups from string passed")
		return nil, fmt.Errorf("Errored out unmarshalling groups from string passed")
	}
	result := make([]*group.DefaultPosixGroup, 0)
	for _, each := range a {
		tmp := each
		result = append(result, &tmp)
	}
	return result, nil
}

func encodeSudoClaims(sudoClaims []string) (string, error) {
	jsonSudoClaims, err := json.Marshal(sudoClaims)
	if err != nil {
		log.Print("Could not marshall the sudoClaims to Json")
		return "", fmt.Errorf("Could not marshall the sudoClaims to Json")
	}
	log.Print("Marshalled sudoClaims to string")
	return string(jsonSudoClaims), nil
}

func decodeSudoClaims(sudoClaimsStr string) ([]string, error) {
	var a []string
	err := json.Unmarshal([]byte(sudoClaimsStr), &a)
	if err != nil {
		log.Print("Errored out unmarshalling sudoClaims from string passed")
		return nil, fmt.Errorf("Errored out unmarshalling sudoClaims from string passed")
	}
	return a, nil
}

func encodePasswdHash(passwdHash string) (string, error) {
	jsonPasswdHash, err := json.Marshal(passwdHash)
	if err != nil {
		log.Print("Could not marshall the passwdHash to Json")
		return "", fmt.Errorf("Could not marshall the passwdHash to Json")
	}
	log.Print("Marshalled passwdHash to string")
	return string(jsonPasswdHash), nil
}

func decodePasswdHash(passwdHashStr string) (string, error) {
	var a string
	err := json.Unmarshal([]byte(passwdHashStr), &a)
	if err != nil {
		log.Print("Errored out unmarshalling passwdHash from string passed")
		return "", fmt.Errorf("Errored out unmarshalling passwdHash from string passed")
	}
	return a, nil
}
