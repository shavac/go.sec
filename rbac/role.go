package rbac

import ()

type Role struct {
	name     string
	provider RoleProvider
}

func MakeRole(name string, provider RoleProvider) *Role{
	return &Role{
		name:name,
		provider: provider,
	}
}

func (r *Role) Type() int {
	return ROLE
}

func (r *Role) Name() string {
	return r.name
}

func (r *Role) Desc() string {
	if d, err := r.provider.RoleDesc(r.Name()); err== nil {
		return d
	}
	return ""
}

func (r *Role) GrantPerm(permname string) error {
	return r.provider.RoleGrantPerm(r.Name(), permname)
}

func (r *Role) GrantRole(rolename string) error {
	return r.provider.RoleGrantRole(r.Name(), rolename)
}

func (r *Role) RevokePerm(permname string) error {
	return r.provider.RoleRevokePerm(r.Name(), permname)
}

func (r *Role) RevokeRole(rolename string) error {
	return r.provider.RoleRevokeRole(r.Name(), rolename)
}

func (r *Role) Drop() error {
	return r.provider.DropRole(r.Name())
}
