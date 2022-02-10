package group

type DefaultPosixGroup struct {
	Gid  *uint16 `json:"gid,omitempty"`
	Name *string `json:"name,omitempty"`
}

func (c *DefaultPosixGroup) GetGroupID() *uint16 {
	return c.Gid
}

func (c *DefaultPosixGroup) GetGroupName() *string {
	return c.Name
}

func (c *DefaultPosixGroup) SetGroupID(gid *uint16) {
	c.Gid = gid
}

func (c *DefaultPosixGroup) SetGroupsName(group *string) {
	c.Name = group
}
