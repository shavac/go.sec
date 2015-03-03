package mem

import "testing"

func TestRecursive(t *testing.T) {
	e := Init()
	e.GrantRole("ceo", "hr_mgr")
	e.GrantRole("hr_mgr", "hr_stf")
	e.GrantRole("hr_mgr", "ceo")
	id, _, _ := e.GetRole("ceo", false)
	f := func(cid int) bool {
		return false
	}
	e.searchRoleGraph(id, f)
}
func TestRecursive2(t *testing.T) {
	e := Init()
	e.GrantRole("ceo", "hr_mgr")
	e.GrantRole("hr_mgr", "hr_stf")
	e.GrantPerm("hr_mgr", "update", "delete")
	e.GrantPerm("hr_stf", "select", "insert")
	id, _, _ := e.GetRole("hr_mgr", false)
	f := func(cid int) bool {
		return false
	}
	e.searchRoleGraph(id, f)
}
