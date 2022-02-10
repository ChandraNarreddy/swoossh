package storage

import (
	"github.com/ChandraNarreddy/swoossh/group"
)

type GroupFilter interface {
}

type GroupSearchResult interface {
	GetGroup() group.Group
}

type GroupSearchResp interface {
	GetGroupSearchResults() []GroupSearchResult
}

type SearchGroups interface {
	SearchGroups(GroupFilter) (GroupSearchResp, error)
}

type SSHGroupStore interface {
	CreateGroup(group.Group) error
	GetGroup(GroupFilter) (group.Group, error)
	UpdateGroup(group.Group) error
	DeleteGroup(group.Group) error
}
