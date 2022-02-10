package authorizedprincipals

import "github.com/ChandraNarreddy/swoossh/sshcert"

type MatchCertClaimToAnExistingAccount interface {
	MatchUserClaimToExistingAccount(cert sshcert.Cert) (bool, string, error)
}

type AddUserToSystem interface {
	AddUserToSystem(userLogin string, cert sshcert.Cert) error
}

type AddMissingGroups interface {
	AddMissingGroups(principal string, cert sshcert.Cert) error
}

type AppendSudoCmd interface {
	AppendSudoCmd(principal string, cert sshcert.Cert) error
}

type SyncUsersGroupMemberships interface {
	SyncUsersGroupMemberships() bool
}

type UserGroupMembershipModify interface {
	UserGroupMembershipModify(principal string, cert sshcert.Cert) error
}

type SyncUserSudoRules interface {
	SyncUserSudoRules() bool
}

type ModifySudoRules interface {
	ModifySudoRules(principal string, cert sshcert.Cert) error
}

type TreatMissingPrincpalInCertAsLocalUser interface {
	TreatMissingPrincpalInCertAsLocalUser() string
}

type CreateUserIfNotExists interface {
	CreateUserIfNotExists() bool
}

type CreateMissingGroups interface {
	CreateMissingGroups() bool
}

type AddSudoCmd interface {
	AddSudoCmd() bool
}

type PrintAuthorizedPrincipalsFile interface {
	PrintAuthorizedPrincipalsFile(user string, cert sshcert.Cert) error
}

type SSHCmdTargetUser interface {
	GetSSHCmdTargetUser() string
}

type Host interface {
	PrintAuthorizedPrincipalsFile
	SSHCmdTargetUser
}
