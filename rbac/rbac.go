package rbac

import (
	//"github.com/shavac/go.sec/rbac/errs"
	"github.com/shavac/go.sec/rbac/mem"
)

var (
	engine     Engine = mem.Engine
	curVersion int64  = engine.GetVersion()
)

func Init(conn string) error {
	return engine.Init(conn)
}

func HasRole(roleName string, hasRoleName string) bool {
	return engine.HasRole(roleName, hasRoleName)
}

func HasAllRole(roleName string, hasRoleNames ...string) bool {
	return engine.HasAllRole(roleName, hasRoleNames...)
}

func HasAnyRole(roleName string, hasRoleNames ...string) bool {
	return engine.HasAnyRole(roleName, hasRoleNames...)
}

func incVersion() {
	engine.IncVersion()
}

func getVersion() int64 {
	return engine.GetVersion()
}

func GetOpsByRes(res string) []string {
	return engine.GetOpsByRes(res)
}

func GetPermsByRole(roleName string) []Perm {
	perms := []Perm{}
	ops, res := engine.GetPermsByRole(roleName)
	if len(ops) != len(res) {
		return nil
	}
	for i, op := range ops {
		if res, err := ResParser.Parse("", res[i]); err == nil {
			perms=append(perms, Perm{op, res})
		}
	}
	return perms
}

func RBACDecision(roleName, res string, ops ...string) bool {
	return engine.RBACDecision(roleName, res, ops...)
}

func GrantRole(grantee, granted string) error {
	return engine.GrantRole(grantee, granted)
}

func GrantPerm(roleName, op, res string) error {
	return engine.GrantPerm(roleName, op, res)
}





