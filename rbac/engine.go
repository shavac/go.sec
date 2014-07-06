package rbac

type Engine interface {
	Init(conn string) error
	IncVersion()
	GetVersion() int64
	GetRole(string) (bool, int, string)
	SaveRole(string, int, string) bool
	GetOpsByRes(res string) []string
	GetPermsByRole(roleName string) (ops []string, res []string)
	HasRole(roleName, hasRoleName string) bool
	HasAllRole(roleName string, hasRoleNames ...string) bool
	HasAnyRole(roleName string, hasRoleNames ...string) bool
	//RBACDecision(roleName, res string, ops ...string) bool
	GrantRole(grantee, granted string) error
	GrantPerm(grantee, op, res string) error
}
