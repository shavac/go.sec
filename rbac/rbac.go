package rbac

import (
	//"github.com/shavac/go.sec/rbac/errs"
	"github.com/shavac/go.sec/rbac/mem"
)

var (
	engine     Engine = mem.Engine
	curVersion int64  = engine.GetVersion()
)

func SetEngine(eng Engine) {
	engine = eng
}

func Init(conn string) error {
	return engine.Init(conn)
}

func HasRole(roleName string, hasRoleName string) bool {
	return engine.HasAllRole(roleName, hasRoleName)
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

func GetPermSetByRole(roleName string) []Perm {
	perms := PermSet{}
	ops, res := engine.GetPermsByRole(roleName)
	if len(ops) != len(res) {
		return nil
	}
	for i, op := range ops {
		if ps, err := NewPerm(res[i], op); err == nil {
			perms = append(perms, *ps)
		}
	}
	return perms
}

func GrantRole(grantee string, granted ...string) error {
	return engine.GrantRole(grantee, granted...)
}

func RevokeRole(revokee string, revoked ...string) error {
	return engine.RevokeRole(revokee, revoked...)
}

func GrantPerm(roleName string, res string, ops ...string) error {
	return engine.GrantPerm(roleName, res, ops...)
}

func RevokePerm(roleName, res string, ops ...string) error {
	return engine.RevokePerm(roleName, res, ops...)
}

func GrantSysPerm(roleName string, ops ...string) error {
	return engine.GrantPerm(roleName, "", ops...)
}

func RevokeSysPerm(roleName string, ops ...string) error {
	return engine.RevokePerm(roleName, "", ops...)
}
