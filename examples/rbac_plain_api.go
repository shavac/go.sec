package main

import (
	"github.com/shavac/go.sec/rbac"
	"log"
)

func main() {
	rbac.NewUser("user1")
	rbac.NewUser("user2")
	rbac.NewUser("user3")
	employee := "oracle://scott:tiger@localhost:1521/scott/emp"
	rbac.GrantRole("user1", "ceo")
	rbac.GrantRole("user2", "hr_mgr")
	rbac.GrantRole("user3", "hr_clk")
	rbac.GrantRole("ceo", "hr_mgr")
	rbac.GrantRole("hr_mgr", "hr_clk")
	rbac.GrantPerm("hr_mgr", employee, "update", "delete")
	rbac.GrantPerm("hr_clk", employee, "select", "insert")
	rbac.GrantGlobalPerm("ceo", "select")
	if !rbac.HasRole("user1", "hr_clk") {
		log.Fatal("user1 is ceo and should have hr_clk role")
	}
	if !rbac.Decision("user1", employee, "delete") {
		log.Fatal("user1 should have delete employee permission")
	}
	if rbac.Decision("user3", employee, "delete") {
		log.Fatal("user3 is hr_clk and should not have delete employee permission")
	}
	if rbac.Decision("hr_clerk", employee, "update", "insert", "delete") {
		log.Fatal("hr_clerk should not have update employee permission")
	}
	if !rbac.DecisionEx("user1", "abc", "select") {
		log.Fatal("user1 should has all select permission on all target")
	}
	rbac.RevokeRole("user1","ceo")
	if rbac.Decision("user1", employee, "select") {
		log.Fatal("user1 should have not any employee permission")
	}
	rbac.DropRole("hr_clk")
	if rbac.HasRole("hr_mgr", "hr_clk") || rbac.HasRole("user1","hr_clk"){
		log.Fatal("hr_clk role is dropped, user1 and hr_mgr should not have this role")
	}
	rbac.RevokePerm("hr_mgr",employee,"delete")
	if rbac.DecisionEx("ceo",employee,"delete") && rbac.DecisionEx("hr_mgr",employee,"delete"){
		log.Fatal("hr_mgr is revoked delete employee permission and ceo should not have it,eather")
	}
	println("all test ok")
}
