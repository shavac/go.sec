package main

import (
	"github.com/shavac/go.sec/rbac"
	"github.com/shavac/go.sec/rbac/mem"
	"log"
)

func main() {
	rbac.SetEngine(mem.Engine)
	if err := rbac.Init("DEFAULT"); err != nil {
		log.Fatal(err.Error())
	}
	user1, _ := rbac.NewUser("user1")
	user2, _ := rbac.NewUser("user2")
	user3, _ := rbac.NewUser("user3")
	roleCEO, _ := rbac.NewRole("ceo")
	roleHrManager, _ := rbac.NewRole("hr_mgr")
	roleHrClerk, _ := rbac.NewRole("hr_clerk")
	rbac.NewRes("all", "oracle://scott:tiger@localhost:1521/scott")
	rbac.NewRes("employee", "oracle://scott:tiger@localhost:1521/scott/emp")
	permSelectEmployee, _ := rbac.NewPerm("employee", "select")
	permDeleteEmployee, _ := rbac.NewPerm("employee", "delete")
	permsUpdateEmployee, _ := rbac.NewPermSet("employee", "update", "insert", "delete")
	permsAllOnAll, _ := rbac.NewPermSet("all", "select", "update", "insert", "delete")
	permMeeting, _ := rbac.NewSysPerm("start_meeting")
	rbac.GrantSysPerm("ceo", "dismiss_meeting")
	user2.Grant(roleHrManager)
	user1.Grant(roleHrClerk)
	rbac.GrantRole("user3", "ceo")
	roleCEO.Grant(permMeeting)
	roleCEO.Grant(permsAllOnAll)
	rbac.GrantRole("hr_manager", "hr_clerk")
	rbac.GrantPerm("hr_clerk", "employee", "select")
	roleHrManager.Grant(permsUpdateEmployee)
	roleHrManager.Revoke(permDeleteEmployee)
	rbac.RevokePerm("hr_manager", "employee", "delete")
	if !rbac.HasRole("user1", "hr_clerk") || !user1.HasRole(roleHrClerk) || !user1.HasPerm(permSelectEmployee) {
		log.Fatal("user1 and hr_manager should have hr_clerk role and select on employee permission")
	}
	if !rbac.RBACDecision("user1", "employee", "delete") || !user1.HasPerm(permDeleteEmployee) {
		log.Fatal("user1 should have delete employee permission")
	}
	if !rbac.RBACDecision("user3", "employee", "delete") || ! user3.HasPerm(permsUpdateEmployee) {
		log.Fatal("user3 is ceo and should have delete employee permission")
	}
	if rbac.RBACDecision("hr_clerk", "employee", "update", "insert", "delete") || roleHrClerk.HasPerm(permsUpdateEmployee) {
		log.Fatal("hr_clerk should not have update employee permission")
	}
}
