package rbac

import (
	"github.com/shavac/go.sec/errs"
	. "github.com/shavac/go.sec/rbac/engine"
)

type Role struct {
	rbacType int
	name     string
	desc     string
}

func NewRole(roleName string) (*Role, error) {
	if id, rbacType, exist := egn.GetRole(roleName, true); !exist {
		return &Role{rbacType: ROLE, name: roleName}, nil
	} else {
		return &Role{rbacType: rbacType, name: roleName, desc: egn.GetDesc(id)}, errs.ErrDupRole
	}
}

func DropRole(roleName string) error {
	return egn.DropRole(roleName)
}

func NewUser(userName string) (*Role, error) {
	r, err := NewRole(userName)
	r.SetAsUser()
	return r, err
}

func DropUser(userName string) error {
	return DropRole(userName)
}

func (r *Role) Name() string {
	return r.name
}

func (r *Role) Desc() string {
	return r.desc
}

func (r *Role) SetDesc(desc string) {
	id, _, _ := egn.GetRole(r.Name(), false)
	egn.SetDesc(id, desc)
	r.desc = desc
}

func (r *Role) SetAsUser() {
	r.rbacType = USER
	egn.SetRoleType(r.Name(), USER)
}

func (r *Role) GrantRole(grantedRoles ...*Role) error {
	for _, gr := range grantedRoles {
		if err := GrantRole(r.Name(), gr.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (r *Role) RevokeRole(revokedRoles ...*Role) error {
	for _, rr := range revokedRoles {
		if err := RevokeRole(r.Name(), rr.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (r *Role) GrantPerm(grantedPerms ...*Perm) error {
	for _, gp := range grantedPerms {
		if err := GrantPerm(r.Name(), gp.Resource().String(), gp.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (r *Role) RevokePerm(revokedPerms ...*Perm) error {
	for _, rp := range revokedPerms {
		if err := RevokePerm(r.Name(), rp.Resource().String(), rp.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (r *Role) Drop() error {
	return egn.DropRole(r.Name())
}

func (r *Role) HasRole(roles ...*Role) bool {
	rl := []string{}
	for _, role := range roles {
		rl = append(rl, role.Name())
	}
	return egn.HasAllRole(r.Name(), rl...)
}

func (r *Role) HasPerm(perms ...*Perm) bool {
	for _, perm := range perms {
		if !egn.Decision(r.Name(), perm.Resource().Name(), perm.Name()) {
			return false
		}
	}
	return true
}

func (r *Role) HasPerm2(perms ...*Perm) bool {
	for _, perm := range perms {
		if !egn.DecisionEx(r.Name(), perm.Resource().Name(), perm.Name()) {
			return false
		}
	}
	return true
}
