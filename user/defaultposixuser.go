package user

import (
	"github.com/ChandraNarreddy/swoossh/group"
	"golang.org/x/crypto/ssh"
)

type DefaultPosixUser struct {
	PrincipalName    *string            `json:"principalName,omitempty"`
	UID              *uint32            `json:"uid,omitempty"`
	PublicKey        ssh.PublicKey      `json:"publicKey,omitempty"`
	PrimaryGroup     group.PosixGroup   `json:"primaryGroup,omitempty"`
	SecondaryGroups  []group.PosixGroup `json:"secondaryGroups,omitempty"`
	LatestPasswdHash *string            `json:"latestPasswdHash,omitempty"`
	SudoClaims       []string           `json:"sudoClaims,omitempty"`
}

func (c *DefaultPosixUser) GetPrincipalName() *string {
	return DefaultPosixUserGetPrincipalName(c)
}
func (c *DefaultPosixUser) SetPrincipalName(principalName *string) {
	DefaultPosixUserSetPrincipalName(c, principalName)
}
func (c *DefaultPosixUser) GetPublicKey() ssh.PublicKey {
	return DefaultPosixUserGetPublicKey(c)
}
func (c *DefaultPosixUser) SetPublicKey(pubkey ssh.PublicKey) {
	DefaultPosixUserSetPublicKey(c, pubkey)
}
func (c *DefaultPosixUser) GetUID() *uint32 {
	return DefaultPosixUserGetUID(c)
}
func (c *DefaultPosixUser) SetUID(uid *uint32) {
	DefaultPosixUserSetUID(c, uid)
}
func (c *DefaultPosixUser) GetPrimaryGroup() group.PosixGroup {
	return DefaultPosixUserGetPrimaryGroup(c)
}
func (c *DefaultPosixUser) SetPrimaryGroup(group group.PosixGroup) {
	DefaultPosixUserSetPrimaryGroup(c, group)
}
func (c *DefaultPosixUser) GetUserSecondaryGroups() []group.PosixGroup {
	return DefaultPosixUserGetUserSecondaryGroups(c)
}
func (c *DefaultPosixUser) SetUserSecondaryGroups(groups []group.PosixGroup) {
	DefaultPosixUserSetUserSecondaryGroups(c, groups)
}
func (c *DefaultPosixUser) GetLatestPasswdHash() *string {
	return DefaultPosixUserGetLatestPasswdHash(c)
}
func (c *DefaultPosixUser) SetLatestPasswdHash(passwdHash *string) {
	DefaultPosixUserSetLatestPasswdHash(c, passwdHash)
}
func (c *DefaultPosixUser) GetUserSudoClaims() []string {
	return DefaultPosixUserGetUserSudoClaims(c)
}
func (c *DefaultPosixUser) SetUserSudoClaims(sudoClaims []string) {
	DefaultPosixUserSetUserSudoClaims(c, sudoClaims)
}

func DefaultPosixUserGetPrincipalName(c *DefaultPosixUser) *string {
	return c.PrincipalName
}

func DefaultPosixUserSetPrincipalName(c *DefaultPosixUser, principalName *string) {
	c.PrincipalName = principalName
}

func DefaultPosixUserGetPublicKey(c *DefaultPosixUser) ssh.PublicKey {
	return c.PublicKey
}

func DefaultPosixUserSetPublicKey(c *DefaultPosixUser, pubkey ssh.PublicKey) {
	c.PublicKey = pubkey
}

func DefaultPosixUserGetUID(c *DefaultPosixUser) *uint32 {
	return c.UID
}
func DefaultPosixUserSetUID(c *DefaultPosixUser, uid *uint32) {
	c.UID = uid
}

func DefaultPosixUserGetPrimaryGroup(c *DefaultPosixUser) group.PosixGroup {
	return c.PrimaryGroup
}

func DefaultPosixUserSetPrimaryGroup(c *DefaultPosixUser, group group.PosixGroup) {
	c.PrimaryGroup = group
}

func DefaultPosixUserGetUserSecondaryGroups(c *DefaultPosixUser) []group.PosixGroup {
	return c.SecondaryGroups
}

func DefaultPosixUserSetUserSecondaryGroups(c *DefaultPosixUser, groups []group.PosixGroup) {
	c.SecondaryGroups = groups
}

func DefaultPosixUserGetLatestPasswdHash(c *DefaultPosixUser) *string {
	return c.LatestPasswdHash
}

func DefaultPosixUserSetLatestPasswdHash(c *DefaultPosixUser, passwdHash *string) {
	c.LatestPasswdHash = passwdHash
}

func DefaultPosixUserGetUserSudoClaims(c *DefaultPosixUser) []string {
	return c.SudoClaims
}

func DefaultPosixUserSetUserSudoClaims(c *DefaultPosixUser, sudoClaims []string) {
	c.SudoClaims = sudoClaims
}
