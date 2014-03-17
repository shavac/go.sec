package rbac

import (
	"sort"
)

var (
	identProvider IdentProvider
	roleProvider  RoleProvider
	resProvider   ResProvider
)

type RoleProvider interface {
	CreateRole(rolename, desc string) (*Role, error)
	GetRoleByName(rolename string) *Role
	DropRole(rolename string) error
	UpdateRole(role *Role) error
	//return all authz guid
	AllAuthz() sort.StringSlice
	//return guids of directly granted roles and permission for an ident
	AuthzByIdent(identname string) sort.StringSlice
	//return guids of directly granted roles and permission for a  role
	AuthzByRole(rolename string) sort.StringSlice
	IdentGrantAuthz(identname, authzguid string) error
	IdentRevokeAuthz(identname, authzguid string) error
	RoleGrantAuthz(rolename, authzguid string) error
	RoleRevokeAuthz(rolename, authzguid string) error
	RoleContainsAuthz(rolename, authzguid string) bool
	IdentHasAuthz(identname, authzguid string) bool
	IdentHasRole(identname, rolename string) bool
	IdentHasPerm(identname, permname string) bool
	IdentHasAllAuthz(identname string, authzguids ...string) bool
	IdentHasAllRoles(identname string, rolenames ...string) bool
	IdentHasAllPerms(identname string, permnames ...string) bool
	IdentHasAnyRole(identname string, rolenames ...string) bool
	IdentHasAnyPerm(identname string, permnames ...string) bool
	RegisterPerm(permname string, resurl ...string) error
	UnRegisterPerm(permname string, resrl ...string) error
	PermsByResUrl(resurl string) sort.StringSlice
}

type IdentProvider interface {
	GetIdentByName(name string) (Identity, error)
}

type ResProvider interface {
	GetResByURL(url string) (Res, error)
}

func SetRoleProvider(rolep RoleProvider) {
	roleProvider = rolep
}

func SetResProvider(resp ResProvider) {
	resProvider = resp
}
