package rbac

import (
	"github.com/shavac/go.sec/rbac/errs"
)

type User struct {
	Role
}

func NewUser(userName string) (*User, error) {
	exist, rType, rDesc := engine.GetRole(userName)
	switch {
	case !exist:
		return &User{Role{name: userName, roleType: USER}}, nil
	case exist && rType == ROLE: // a role with same name already exists
		return nil, errs.ErrDupRole
	case exist && rType == USER:
		return &User{Role{name: userName, roleType: rType, desc: rDesc}}, errs.ErrDupUser
	default:
		return nil, errs.ErrEngine
	}
}
