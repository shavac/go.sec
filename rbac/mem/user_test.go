package mem

import (
	"testing"
)

func TestUser(t *testing.T) {
	NewRole("admin","administrator")
	NewRole("hr_mgr","human resource manager")
	NewRole("hr_stf","human resource staff")
	u,_ := NewUser("user1","password")
	u.GrantRole("admin")
	r, err := GetRoleByName("admin")
	if err != nil {
		t.Errorf("get admin role")
	}
	r.GrantRole("hr_mgr")
	hr_mgr, _ := GetRoleByName("hr_mgr")
	hr_mgr.GrantRole("hr_stf")
	hr_stf, _ := GetRoleByName("hr_stf")
	
	hr_stf.GrantPerm
}
