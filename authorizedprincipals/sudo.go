package authorizedprincipals

type SudoCmd interface {
	addSudoCommand() error
}

type DefaultSudoCmd struct {
}
