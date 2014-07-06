package main

import (
	"fmt"
	"github.com/shavac/go.sec/rbac"
)

func main() {
	if err := rbac.Init("DEFAULT"); err != nil {
		fmt.Fatal(err.Error())
	}
	User1, _ := rbac.NewUser("user1")
	User2, _ := rbac.NewUser("user2")
	User3, _ := rbac.NewUser("user3")
	roleCEO, _ := rbac.NewRole("ceo")
	roleHrManager, _ := rbac.NewRole("hr_mgr")
	roleHrClerk, _ := rbac.NewRole("hr_clerk")
	resEmployee, _ := rbac.NewRes("employee", "oracle://scott:tiger@localhost:1521/scott/emp")
	permSelectEmployee, _ := rbac.NewPerm("employee", "select")
	permUpdateEmployee, _ := rbac.NewPerm("employee", "insert","update","delete")
	permMeeting, _ := rbac.NewSysPerm("have_meeting")
	rbac.GrantSysPerm("ceo","dismiss_meeting")
	User2.Grant(roleHrManager)
	User1.Grant(roleHrClerk)
	roleCEO.Grant(permMeeting)
	roleCEO.Grant(roleHrManager)
	rbac.GrantRole("hr_manager","hr_clerk")
	rbac.GrantPerm("hr_clerk", "employee","select")
	roleHrManager.Grant(permUpdateEmployee)
	rbac.GrantPerm("hr_manager", "employee","delete")
	if !rbac.HasRole("user1", "hr_clerk") || !roleHrManager.HasRole(roleHrClerk) {
		fmt.Fatal("user1 and hr_manager should have hr_clerk role")
	}
	if !rbac.ResAccessDecision("user1", "employee", "delete") || !User1.HasPerm(permDeleteEmployee) {
		fmt.Fatal("user1 should have delete employee permission")
	}
	if rbac.ResAccessDecision("user3", "employee", "delete") || User3.HasPerm(permDeleteEmployee) {
		fmt.Fatal("user3 should not have delete employee permission")
	}
	if rbac.ResAccessDecision("hr_clerk", "employee", "update", "insert", "delete") || roleHrClerk.HasPerm(permUpdateEmployee) {
		fmt.Fatal("hr_clerk should not have update employee permission")
	}
}
