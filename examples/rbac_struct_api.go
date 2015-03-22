package main

import (
    "github.com/shavac/go.sec/rbac"
    _ "github.com/shavac/go.sec/rbac/engine"
    _ "github.com/shavac/go.sec/rbac/engine/mongo"
    "log"
    "gopkg.in/mgo.v2"
    "time"
    "math/rand"
    "fmt"
)

func main() {
	sess, err := mgo.Dial("localhost")
	if err != nil {
		panic("cannot connect to localhost")
	}
	db := sess.DB(fmt.Sprintf("rbac_%d", rand.New(rand.NewSource(time.Now().UnixNano())).Int31n))
	rbac.Init(db)
	user1, _ := rbac.NewUser("user1")
	user2, _ := rbac.NewUser("user2")
	user3, _ := rbac.NewUser("user3")
	roleCEO, _ := rbac.NewRole("ceo")
	roleHrManager, _ := rbac.NewRole("hr_mgr")
	roleHrClerk, _ := rbac.NewRole("hr_clk")
	permMeeting, _ := rbac.NewGlobalPerm("start_meeting")
	employee := "oracle://scott:tiger@localhost:1521/scott/emp"
	all := "oracle://scott:tiger@localhost:1521/scott"
	permSelectEmployee, _ := rbac.NewPerm("select", rbac.Res(employee))
	permUpdateEmployee, _ := rbac.NewPerm("update", rbac.Res(employee))
	permDeleteEmployee, _ := rbac.NewPerm("delete", rbac.Res(employee))
	permSelectAll, _ := rbac.NewPerm("select", rbac.Res(all))
	user2.GrantRole(roleHrManager)
	user3.GrantRole(roleHrClerk)
	rbac.GrantRole("user1", "ceo")
	rbac.GrantRole("hr_mgr", "hr_clk")
	roleCEO.GrantRole(roleHrManager)
	roleCEO.GrantPerm(permSelectAll)
	roleCEO.GrantPerm(permMeeting)
	rbac.GrantPerm("hr_clk", employee, "select", "insert")
	roleHrManager.GrantPerm(permUpdateEmployee)
	roleHrManager.GrantPerm(permDeleteEmployee)
	//rbac.RevokePerm("hr_manager", "employee", "delete")
	if !rbac.HasRole("user1", "hr_clk") || !user1.HasRole(roleHrClerk) || !user1.HasPerm(permSelectEmployee) {
		log.Fatal("user1 and hr_mgr should have hr_clk role and select on employee permission")
	}
	if !rbac.Decision("user1", employee, "delete") || !user1.HasPerm(permDeleteEmployee) {
		log.Fatal("user1 is ceo and should have delete employee permission")
	}
	roleHrManager.RevokePerm(permDeleteEmployee)
	if rbac.Decision("user1", employee, "delete") || user1.HasPerm(permDeleteEmployee) {
		log.Fatal("delete employee is revoked from hr_mgr, and user1 is ceo and should not have delete employee permission")
	}
	if rbac.Decision("hr_clerk", employee, "update", "insert", "delete") || roleHrClerk.HasPerm(permUpdateEmployee) {
		log.Fatal("hr_clerk should not have update employee permission")
	}
	if !rbac.DecisionEx("user3", employee, "select") {
		log.Fatal("user3 should has all select permission on all target")
	}
	if !rbac.DecisionEx("user1", "", "start_meeting") {
		log.Fatal("user1 is ceo and can start meeting")
	}
	db.DropDatabase()
	println("all test ok")
}
