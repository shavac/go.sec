package mem

import (
	"testing"
	//"github.com/shavac/go.sec/resource"
	. "github.com/shavac/go.sec/rbac/engine"
)

func init() {
	var _ RBACProvider = Init()
}

func TestGetDropRole(t *testing.T) {
	e := Init()
	ceoid, _, _ := e.GetRole("ceo", true)
	e.GrantRole("ceo", "hr_mgr")
	e.GrantRole("ceo", "acct_mgr")
	if id, _, exist := e.GetRole("ceo", false); !exist || id != ceoid {
		t.Fatal("ceo not created")
	}
	if _, _, exist := e.GetRole("hr_mgr", false); !exist {
		t.Fatal("hr_mgr not created")
	}
	if e.DropRole("hr_mgr") != nil {
		t.Fatal("error dropping hr_mgr role")
	}
	if e.HasAllRole("ceo", "hr_mgr", "acct_mgr") {
		t.Fatal("hr_mgr is dropped, ceo role shouldnot have hr_mgr role")
	}
	if !e.HasAnyRole("ceo", "hr_mgr", "acct_mgr") {
		t.Fatal("hr_mgr is dropped, but ceo role still have acct_mgr role")
	}
}

func TestGrantRevokeDropPerm(t *testing.T) {
	e := Init()
	e.GrantRole("ceo", "hr_mgr")
	e.GrantRole("hr_mgr", "hr_stf")
	e.GrantRole("cfo", "acct_mgr")
	e.GrantRole("acct_mgr", "acct_stf")
	e.GrantPerm("hr_mgr", "employee", "update", "delete")
	e.GrantPerm("hr_stf", "employee", "select", "insert")
	e.GrantPerm("acct_mgr", "employee", "update")
	e.DropPerm("delete", "employee")
	if e.Decision("ceo", "employee", "delete") {
		t.Fatal("permission of delete employee is dropped,ceo should not have it")
	}
	e.RevokePerm("ceo", "employee", "select") // indirect permission cannot be revoked directly
	if !e.Decision("ceo", "employee", "select") {
		t.Fatal("permission of select employee is a indirect permission,ceo should not be revoked this permission")
	}
	e.RevokePerm("hr_stf", "employee", "select") // direct permission can be revoked directly
	if e.Decision("ceo", "employee", "select") {
		t.Fatal("permission of select employee for hr_stf is a direct permission,ceo should not have this permission")
	}
}

func TestHasAllAnyRole(t *testing.T) {
	e := Init()
	e.GrantRole("ceo", "hr_mgr")
	e.GrantRole("hr_mgr", "hr_stf")
	e.GrantRole("cfo", "acct_mgr")
	e.GrantRole("acct_mgr", "acct_stf")
	e.RevokeRole("cfo", "acct_stf") //should not tak effect
	if !e.HasAllRole("ceo", "hr_mgr", "hr_stf") {
		t.Fatal("ceo should have hr_mgr and hr_stf role")
	}
	if e.HasAllRole("ceo", "acct_mgr") {
		t.Fatal("ceo should have not have acct_mgr role")
	}
	if !e.HasAnyRole("cfo", "hr_stf", "acct_stf") {
		t.Fatal("cfo should have acct_stf role")
	}
	e.RevokeRole("cfo", "acct_mgr") //should revoke acct_mgr and followed acct_stf
	if e.HasAnyRole("cfo", "acct_stf") {
		t.Fatal("cfo should not have acct_stf role")
	}
}

func TestRBACDecision(t *testing.T) {
	e := Init()
	e.GrantRole("ceo", "hr_mgr")
	e.GrantRole("hr_mgr", "hr_stf")
	e.GrantRole("cfo", "acct_mgr")
	e.GrantRole("acct_mgr", "acct_stf")
	e.GrantPerm("hr_mgr", "employee", "update", "delete")
	e.GrantPerm("hr_stf", "employee", "select", "insert")
	e.GrantPerm("acct_mgr", "employee", "update")
	if !e.Decision("ceo", "employee", "insert", "delete", "update", "select") {
		t.Fatal("ceo should has permission of update employee")
	}
	if !e.Decision("hr_mgr", "employee", "select", "delete", "update", "insert") {
		t.Fatal("hr_mgr should has permission of idus employee")
	}
	if e.Decision("hr_stf", "employee", "insert", "delete", "update", "select") {
		t.Fatal("hr_stf should not has permission of update employee")
	}
	e.DropRole("hr_mgr")
	if e.Decision("ceo", "employee", "insert", "delete", "update", "select") {
		t.Fatal("hr_mgr role had beed dropped, ceo should not has permission of update employee")
	}
}

func TestRBAC2Decision(t *testing.T) {
	e := Init()
	e.GrantRole("admin", "sports_admin")
	e.GrantRole("admin", "finance_admin")
	e.GrantRole("admin", "visitor")
	e.GrantRole("sports_admin", "visitor")
	e.GrantRole("finance_admin", "visitor")
	e.GrantPerm("visitor", "", "GET") //global GET permission
	e.GrantPerm("sports_admin", "http://sina.com/sports", "UPLOAD", "REMOVE")
	e.GrantPerm("finance_admin", "http://sina.com/finance", "UPLOAD", "REMOVE")
	if !e.DecisionEx("admin", "http://sina.com/sports/nba", "UPLOAD", "REMOVE", "GET") {
		t.Fatal("admin should have all permission")
	}
	if !e.DecisionEx("sports_admin", "http://sina.com/finance/fond", "GET") {
		t.Fatal("sports_admin should have GET any page permission")
	}
	if !e.DecisionEx("sports_admin", "http://sohu.com", "GET") {
		t.Fatal("sports_admin should have GET any page permission")
	}
	if e.DecisionEx("admin", "http://sina.com", "DOWNLOAD") {
		t.Fatal("admin should not have un-existent permission")
	}
}
