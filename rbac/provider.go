package rbac

import ()

type RoleProvider interface {
	Init()
	CreateRole(rolename string, desc string) (*Role, error)
	GetRoleByName(rolename string) *Role
	DropRole(rolename string) error
	RoleDesc(rolename string) (string, error)
	SetRoleDesc(rolename string, desc string) error
	AllRoleNames() []string
	RolesByIdent(identname string) ([]string, error)
	PermsByRole(rolename string) ([]string, error)
	IdentGrantRole(identname string, rolename string) error
	IdentRevokeRole(identname string, rolename string) error
	RoleGrantPerm(rolename string, permname string) error
	RoleRevokePerm(rolename string, permname string) error
	RoleGrantRole(to string, from string) error
	RoleRevokeRole(to string, from string) error
	IdentHasRole(identname string, rolename string) bool
	IdentHasPerm(identname string, permname string) bool
	IdentHasAllRoles(identname string, rolenames ...string) bool
	IdentHasAllPerms(identname string, permnames ...string) bool
	IdentHasAnyRole(identname string, rolenames ...string) bool
	IdentHasAnyPerm(identname string, permnames ...string) bool
}

type IdentProvider interface {
	Init()
	GetIdentByName(name string) (Identity, error)
}

type PermProvider interface {
	Init()
	SavePerm(perm Permission) error
	DelPermByName(permname string) error
	GetPermByName(permname string) Permission
	PermByResGuid(resguid string) []*ResourcePermission
}

type RBACProvider interface {
	PermsByIdentAndResGuid(identname, resguid string) bool
}
