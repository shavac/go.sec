package rbac

type Engine interface {
	Init(conn string) error
	IncVersion() int
	GetVersion() int
	GetRole(string) (bool, int, string)
	SaveRole(string, int, string) bool
	GetOpsByRes(res string) []string
	GetPermsByRole(roleName string) (ops []string, res []string)
	HasAllRole(roleName string, hasRoleNames ...string) bool
	HasAnyRole(roleName string, hasRoleNames ...string) bool
	HasAllPerm(roleName, res string, ops ...string) bool
	GrantRole(grantee string, granted ...string) error
	GrantPerm(grantee string, res string, ops ...string) error
	RevokeRole(revokee string, revoked ...string) error
	RevokePerm(roleName string, res string, ops ...string) error
	ResAlias(alias, resString string) bool
	Gc()
}
