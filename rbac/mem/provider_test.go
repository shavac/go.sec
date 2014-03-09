package mem

import (
	"testing"
	"github.com/shavac/go.sec/rbac"
)

func TestIdentGrantRole(t *testing.T) {
	rc := NewRoleContainer()
	rc.IdentGrantRole("user1", "admin")
	if !rc.IdentHasRole("user1", "admin") {
		t.Errorf("error granting role_admin to user1")
	}
	if rc.IdentRevokeRole("user1", "admin1") !=  rbac.ErrorRoleNotGranted {
		t.Errorf("error revoking role not granted")
	}
	if 	rc.IdentRevokeRole("user1", "admin")==nil && rc.IdentHasRole("user1", "admin") {
		t.Errorf("revoked role but still exist")
	}
	rc.IdentGrantRole("steve", "account")
	rc.IdentGrantRole("steve", "hr")
	if rc.IdentHasAllRoles("steve", "hr", "mgr") {
		t.Errorf("steve should not have all roles")
	}
	if ! rc.IdentHasAllRoles("steve", "hr", "account") {
		t.Errorf("steve should have all roles")
	}
	if ! rc.IdentHasAnyRole("steve", "hr", "mgr") {
		t.Errorf("steve should have hr role")
	}
	if rc.IdentHasAllRoles("steve", "app", "mgr") {
		t.Errorf("steve should not have any roles")
	}
}

func TestRoleGrantRole(t *testing.T) {
	rc := NewRoleContainer()
	rc.CreateRole("hr_manager","human resource manager")
	rc.CreateRole("hr_staff","human resource staff")
	rc.CreateRole("staff","common staff")
	rc.RoleGrantRole("hr_manager", "hr_staff")
	rc.RoleGrantRole("hr_staff", "staff")
	rc.IdentGrantRole("user1","hr_manager")
	if rs := rc.RolesByIdent("user1") ; rs.Len() != 1 {
		t.Errorf("number of roles granted to user1 should be 1")
	}
	if ! rc.IdentHasAllRoles("user1","hr_staff","staff") {
		t.Errorf("steve should have hr_staff indirectly role")
	}
	rc.RoleRevokeRole("hr_staff","staff")
	if rc.IdentHasRole("user1","staff") {
		t.Errorf("steve should not have staff indirectly role")
	}
}

func TestSysPerm(t *testing.T) {
	pp:= NewPermContainer()
	pp.SavePerm(rbac.NewSysPermission("sel"))
	pp.SavePerm(rbac.NewSysPermission("del"))
	pp.DelPermByName("del")
	if pp.GetPermByName("sel").Name()!="sel" {
		t.Errorf("sel permission cannot get")
	}
	if pp.GetPermByName("del") != nil {
		t.Errorf("del permission shouldn't be get")
	}
}
