package rbac

import (
	"github.com/shavac/go.sec/rbac/errs"
)

type Role struct {
	name     string
	roleType int
	desc     string
}

func NewRole(roleName string) (*Role, error) {
	if exist, rType, rDesc := engine.GetRole(roleName); !exist {
		return &Role{name: roleName, roleType: ROLE}, nil
	} else {
		return &Role{name: roleName, roleType: rType, desc: rDesc}, errs.ErrDupRole
	}
}

func (r *Role) RBACType() int {
	return r.roleType
}

func (r *Role) Name() string {
	return r.name
}

func (r *Role) Desc() string {
	return r.desc
}

func (r *Role) SetDesc(desc string) {
	r.desc = desc
}

func (r *Role) Grant(aus ...authz) error {
	for _, au := range aus {
		switch a := au.(type) {
		case *User:
			return errs.ErrNotGrantable
		case *Role:
			if a.RBACType() == USER {
				return errs.ErrNotGrantable
			}
			if err := GrantRole(r.Name(), a.Name()); err != nil {
				return err
			}
		case *Perm:
			if err := GrantPerm(r.Name(), a.Op(), a.Res().String()); err != nil {
				return err
			}
		case PermSet:
			for _, p := range a {
				if err := GrantPerm(r.Name(), p.Op(), p.Res().String()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *Role) Revoke(au ...authz) error {
	return nil
}

func (r *Role) Drop() error {
	return nil
}

func (r *Role) Save() bool {
	return engine.SaveRole(r.Name(), r.RBACType(), r.Desc())
}

func (r *Role) HasRole(roles ...*Role) bool {
	for _, role := range roles {
		if !r.HasAuthz(role) {
			return false
		}
	}
	return true
}

func (r *Role) HasPerm(perms ...authz) bool {
	for _, perm := range perms {
		if !r.HasAuthz(perm) {
			return false
		}
	}
	return true
}

func (r *Role) HasAuthz(aus authz) bool {
	switch a := aus.(type) {
	case *Role, *User:
		if !engine.HasAllRole(a.(*Role).Name()) {
			return false
		}
	case *Perm:
		if !engine.HasAllPerm(r.Name(), a.Res().String(), a.Op()) {
			return false
		}
	case PermSet:
		for _, p := range a {
			if !engine.HasAllPerm(r.Name(), p.Res().String(), p.Op()) {
				return false
			}
		}
	default:
		return false
	}
	return true
}
