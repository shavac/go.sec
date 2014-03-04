package rbac

type Identity interface {
	Id() string
	HasRole(rolename string) bool
	HasPerm(permname string) bool
	HasAllRoles(rolenames ...string) bool
	HasAllPerms(permnames ...string) bool
	HasAnyRole(rolenames ...string) bool
	HasAnyPerm(permnames ...string) bool
	GrantRole(rolename string) error
	RevokeRole(rolename string) error
}
