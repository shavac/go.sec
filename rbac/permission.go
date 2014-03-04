package rbac

type Permission interface {
	Name() string
	Type() int
}

type ResourcePermission struct {
	name string
	res  Resource
}

func (rp *ResourcePermission) Name() string {
	return rp.name
}

func (rp *ResourcePermission) Type() int {
	return RESPERM
}

func (rp *ResourcePermission) Res() Resource {
	return rp.res
}


func NewResPermission(name string, res Resource) *ResourcePermission {
	return &ResourcePermission{
		name: name,
		res:  res,
	}
}

type SystemPermission struct {
	name string
}

func (sp *SystemPermission) Name() string {
	return sp.name
}

func (sp *SystemPermission) Type() int {
	return SYSPERM
}

func NewSysPermission(name string) *SystemPermission {
	return &SystemPermission{ name }
}
