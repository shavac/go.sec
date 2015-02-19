package rbac

import (
	"github.com/shavac/go.sec/rbac/mem"
)

var (
	engine     Engine = mem.Engine
	curSerial int64  = engine.GetSerial()
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

func incSerial() {
	engine.IncSerial()
}

func getSerial() int64 {
	return engine.GetSerial()
}

func GetOpsByRes(res string) []string {
	return engine.GetOpsByRes(res)
}

func GetPermSetByRole(roleName string) PermSet {
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
