package rbac

import (
	"github.com/shavac/go.sec/rbac/engine"
)

var (
	egn engine.RBACProvider
)

func Init(conn interface{}) error {
	e, err := engine.Factory(conn)
	egn=e
	return err
}

func HasRole(roleName string, hasRoleName string) bool {
	return egn.HasAllRole(roleName, hasRoleName)
}

func HasAllRole(roleName string, hasRoleNames ...string) bool {
	return egn.HasAllRole(roleName, hasRoleNames...)
}

func HasAnyRole(roleName string, hasRoleNames ...string) bool {
	return egn.HasAnyRole(roleName, hasRoleNames...)
}

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

func GrantGlobalPerm(roleName string, perm ...string) error {
	return egn.GrantPerm(roleName, "", perm...)
}

func RevokeGLobalPerm(roleName string, perm ...string) error {
	return egn.RevokePerm(roleName, "", perm...)
}

func Decision(roleName string, res string, perm ...string) bool {
	return egn.Decision(roleName, res, perm...)
}

func DecisionEx(roleName string, res string, perm ...string) bool {
	return egn.DecisionEx(roleName, res, perm...)
}
