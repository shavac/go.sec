package mem

import (
	"github.com/shavac/go.sec/rbac"
)

func NewRole(rolename, roledesc string) (*rbac.Role, error) {
	return RoleProvider.CreateRole(rolename, roledesc)
}

func GetRoleByName(rolename string) *rbac.Role {
	return RoleProvider.GetRoleByName(rolename)
}
