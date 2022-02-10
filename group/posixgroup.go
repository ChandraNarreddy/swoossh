package group

type GroupID interface {
	GetGroupID() *uint16
	SetGroupID(*uint16)
}

type PosixGroup interface {
	Group
	GroupID
}
