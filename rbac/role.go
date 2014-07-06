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
	if exist, rType, rDesc:= engine.GetRole(roleName); ! exist {
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
	for _, au:= range aus {
		switch a := au.(type) {
		case *User:
			return errs.ErrNotGrantable
		case *Role:
			if err := GrantRole(r.Name(), a.Name()); err != nil {
				return err
			}
		case *Perm:
			if err := GrantPerm(r.Name(), a.Op(), a.Res().String()); err != nil {
				return err
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
