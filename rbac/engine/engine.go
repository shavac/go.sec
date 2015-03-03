package engine

type RBACProvider interface {
	GrantRole(grantee string, granted ...string) error
	RevokeRole(revokee string, revoked ...string) error
	GrantPerm(roleName string, res string, perms ...string) error
	RevokePerm(roleName string, res string, perms ...string) error
	GetRole(roleName string, create bool) (id int, rbacType int, exist bool)
	DropRole(roleName string) error
	GetPerm(permName, resString string, create bool) (id int, exist bool)
	DropPerm(permName, resString string) error
	SetDesc(id int, desc string) (exist bool)
	GetDesc(id int) string
	SetRoleType(roleName string, rbacType int) error
	HasAllRole(roleName string, hasRoleNames ...string) bool
	HasAnyRole(roleName string, hasRoleNames ...string) bool
	Decision(roleName string, res string, perms ...string) bool
	DecisionEx(roleName string, res string, perms ...string) bool
}
