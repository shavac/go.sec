package engine

type RBACProvider interface {
	GrantRole(grantee string, granted ...string) error
	RevokeRole(revokee string, revoked ...string) error
	GrantPerm(roleName string, res string, perms ...string) error
	RevokePerm(roleName string, res string, perms ...string) error
	GetRole(roleName string, create bool) (exist bool, id int)
	DropRole(roleName string) error
	GetPerm(permName, resString string, create bool) (exist bool, id int)
	DropPerm(permName, resString string) error
	SetDesc(id int, desc string) (exist bool)
	GetDesc(id int) string
	HasAllRole(roleName string, hasRoleNames ...string) bool
	HasAnyRole(roleName string, hasRoleNames ...string) bool
	RBACDecision(roleName string, res string, perms ...string) bool
	RBAC2Decision(roleName string, res string, perms ...string) bool
}
