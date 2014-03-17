package rbac

import (
	"strings"
)

type Role struct {
	name string
	desc string
}

func NewRole(rolename, desc string) (*Role, error) {
	return roleProvider.CreateRole(strings.ToUpper(rolename), desc)
}

func GetRoleByName(rolename string) *Role {
	return roleProvider.GetRoleByName(rolename)
}

func (r *Role) Type() int {
	return ROLE
}

func (r *Role) Name() string {
	return r.name
}

func (r *Role) AuthzCode() string {
	return "ROLE_" + r.name
}

func (r *Role) Desc() string {
	return r.desc
}

func (r *Role) Equals(a authz) bool {
	return r.AuthzCode() == a.AuthzCode()
}

func (r *Role) Contains(a authz) bool {
	return roleProvider.RoleContainsAuthz(r.Name(), a.AuthzCode())
}

func (r *Role) BelongsTo(a authz) bool {
	switch a.Type() {
	case IDENT:
		return roleProvider.IdentHasRole(a.Name(), r.Name())
	case ROLE:
		return roleProvider.RoleContainsAuthz(a.Name(), r.AuthzCode())
	default:
		return false
	}
}

func (r *Role) Grant(aut authz) error {
	return roleProvider.RoleGrantAuthz(r.Name(), aut.AuthzCode())
}

func (r *Role) Revoke(aut authz) error {
	return roleProvider.RoleRevokeAuthz(r.Name(), aut.AuthzCode())
}

func (r *Role) Drop() error {
	err := roleProvider.DropRole(r.Name())
	if err == nil {
		r = nil
	}
	return err
}
