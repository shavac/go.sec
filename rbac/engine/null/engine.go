package null

import (
	"github.com/shavac/go.sec/rbac/engine"
	"fmt"
)

type nullEngine struct {
}

func init() {
	engine.Register(new(nullEngine), Init)
}

func Init(conn interface{}) (engine.RBACProvider, error) {
	if _, ok := conn.(*nullEngine); !ok {
		return nil, fmt.Errorf("need type *null, got %T\n", conn)
	} else {
		return &nullEngine{}, nil
	}
}

func (e *nullEngine) currentSerial() int {
	return 0
}

func (e *nullEngine) nextSerial() int {
	return 1
}

func (e *nullEngine) GetRole(roleName string, create bool) (int, int, bool) {
	return 0, 0, false
}

func (e *nullEngine) SetRoleType(roleName string, rbacType int) error {
	return nil
}

func (e *nullEngine) DropRole(roleName string) error {
	return nil
}

func (e *nullEngine) GrantRole(grantee string, grants ...string) error {
	return nil
}

func (e *nullEngine) RevokeRole(revokee string, revoked ...string) error {
	return nil
}

func (e *nullEngine) GetPerm(permName, resString string, create bool) (id int, exist bool) {
	return 0, false
}

func (e *nullEngine) DropPerm(permName, resString string) error {
	return nil
}

func (e *nullEngine) GrantPerm(roleName, resString string, perms ...string) error {
	return nil
}

func (e *nullEngine) RevokePerm(roleName string, res string, perms ...string) error {
	return nil
}

func (e *nullEngine) SetDesc(id int, desc string) bool {
	return false
}

func (e *nullEngine) GetDesc(id int) string {
	return ""
}

func (e *nullEngine) HasAllRole(roleName string, hasRoleNames ...string) bool {
	return true
}

func (e *nullEngine) HasAnyRole(roleName string, hasRoleNames ...string) bool {
	return false
}

func (e *nullEngine) searchRoleGraph(rootId int, f func(id int) bool) bool {
	return false
}

func (e *nullEngine) Decision(roleName string, res string, perms ...string) bool {
	return false
}

func (e *nullEngine) DecisionEx(roleName string, res string, perms ...string) bool {
	return true
}
