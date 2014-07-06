package rbac

import (
	"github.com/shavac/go.sec/rbac/errs"
)

type User struct {
	name     string
	roleType int
	desc     string
}

func NewUser(userName string) (*User, error) {
	exist, rType, rDesc := engine.GetRole(userName)
	switch {
	case !exist:
		return &User{name: userName, roleType: USER}, nil
	case exist && rType == ROLE: // a role with same name already exists
		return nil, errs.ErrDupRole
	case exist && rType == USER:
		return &User{name: userName, roleType: rType, desc: rDesc}, errs.ErrDupUser
	default:
		return nil, errs.ErrEngine
	}
}

func (r *User) RBACType() int {
	return r.roleType
}

func (r *User) Name() string {
	return r.name
}

func (r *User) Desc() string {
	return r.desc
}

func (r *User) SetDesc(desc string) {
	r.desc = desc
}

func (r *User) Grant(aus ...authz) error {
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

func (r *User) Revoke(au ...authz) error {
	return nil
}

func (r *User) Drop() error {
	return nil
}
