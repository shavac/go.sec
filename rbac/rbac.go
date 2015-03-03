package rbac

import (
	"github.com/shavac/go.sec/rbac/engine"
	"github.com/shavac/go.sec/rbac/engine/mem"
)

var (
	egn           engine.RBACProvider = mem.Init()
	currentSerial                     = egn.CurrentSerial()
)

func HasRole(roleName string, hasRoleName string) bool {
	return egn.HasAllRole(roleName, hasRoleName)
}

func HasAllRole(roleName string, hasRoleNames ...string) bool {
	return egn.HasAllRole(roleName, hasRoleNames...)
}

func HasAnyRole(roleName string, hasRoleNames ...string) bool {
	return egn.HasAnyRole(roleName, hasRoleNames...)
}

/*func GetPermsByRole(roleName string) []string {
	return engine.GetPermsByRole(roleName)
}
*/

func GrantRole(grantee string, granted ...string) error {
	return egn.GrantRole(grantee, granted...)
}

func RevokeRole(revokee string, revoked ...string) error {
	return egn.RevokeRole(revokee, revoked...)
}

func GrantPerm(roleName string, res string, perm ...string) error {
	return egn.GrantPerm(roleName, res, perm...)
}

func RevokePerm(roleName, res string, perm ...string) error {
	return egn.RevokePerm(roleName, res, perm...)
}

func GrantSysPerm(roleName string, perm ...string) error {
	return egn.GrantPerm(roleName, "", perm...)
}

func RevokeSysPerm(roleName string, perm ...string) error {
	return egn.RevokePerm(roleName, "", perm...)
}

func RBACDecision(roleName string, res string, perm ...string) bool {
	return egn.RBACDecision(roleName, res, perm...)
}
