package mem

import (
//"github.com/shavac/go.sec/rbac/errs"
)

var (
	Engine *engine
)

func init() {
	Engine = &engine{}
}

type engine struct {
}

func (e *engine) Init(string) error {
	return nil
}

func (e *engine) GetVersion() int64 {
	return 0
}

func (e *engine) IncVersion() {
}

func (e *engine) GetRole(roleName string) (bool, int, string) {
	return false, 0, ""
}

func (e *engine) SaveRole(roleName string, roleType int, desc string) bool {
	return false
}

func (e *engine) HasRole(roleName, HasRoleName string) bool {
	return false
}

func (e *engine) HasAllRole(roleName string, HasRoleNames ...string) bool {
	return false
}

func (e *engine) HasAnyRole(roleName string, HasRoleNames ...string) bool {
	return false
}

func (e *engine) GrantRole(grantee, granted string) error {
	return nil
}

func (e *engine) GrantPerm(roleName, op, res string) error {
	return nil
}

func (e *engine) GetOpsByRes(res string) []string {
	return []string{}
}

func (e *engine) GetPermsByRole(roleName string) ([]string, []string) {
	return nil, nil
}

func (e *engine) RBACDecision(roleName, res string, ops ...string) bool {
	return false
}
