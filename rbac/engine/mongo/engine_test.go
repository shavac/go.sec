package mongo

import (
	"github.com/shavac/go.sec/errs"
	"gopkg.in/mgo.v2"
	"testing"
)

var e *mongoEngine

func init() {
	sess, err := mgo.Dial("localhost")
	if err != nil {
		panic("cannot connect to localhost")
	}
	db := sess.DB("rbac")
	p, err := Init(db)
	if err != nil {
		panic("Initializing")
	}
	e = p.(*mongoEngine)
}

func TestSequence(t *testing.T) {
	seq := e.currentId()
	for i := seq; i < seq+5; i++ {
		if e.nextId() != i+1 {
			t.Fatal("nextSerial failed at seq ", i)
		}
	}
}

func TestGetDropRole(t *testing.T) {
	id, tp, _ := e.GetRole("hr_mgr", true)
	id2, tp2, ex := e.GetRole("hr_mgr", false)
	e.GetRole("ceo", false)
	e.SetRoleType("hr_mgr", 0)
	if id != id2 || tp != tp2 || !ex {
		t.Fatal("error get role")
	}
	e.GrantRole("ceo", "hr_mgr")
	if err := e.DropRole("hr_mgr"); err != nil {
		t.Fatal("drop role error:", err.Error())
	}
	if err := e.DropRole("ceo"); err != nil {
		t.Fatal("drop role error:", err.Error())
	}
}

func TestGrantRevokeRole(t *testing.T) {
	if err := e.GrantRole("hr_mgr", "hr_staff", "staff"); err != nil {
		t.Fatal("error grant role:", err.Error())
	}
	if err := e.GrantRole("ceo", "hr_mgr", "staff"); err != nil {
		t.Fatal("error grant role:", err.Error())
	}
	if err := e.RevokeRole("hr_mgr", "hr_staff"); err != nil {
		t.Fatal("error revoke role:", err.Error())
	}
}

/*
func (e *mongoEngine) clear() {
	e.C(RoleCol.name).DropCollection()
	e.C(SeqCol.name).DropCollection()
}

func (e *mongoEngine) reset() {
	e.clear()
	rp, _ :=Init(e.Database)
	e=rp.(*mongoEngine)
}

*/

func TestHasAllAnyRole(t *testing.T) {
	e.GetRole("cfo", true)
	e.GetRole("cto", true)
	if err := e.GrantRole("ceo", "hr_manager", "staff"); err != nil {
		t.Fatal("error grant role:", err.Error())
	}
	if err := e.GrantRole("hr_manager", "hr_staff", "staff"); err != nil {
		t.Fatal("error grant role:", err.Error())
	}
	if !e.HasAllRole("hr_manager", "hr_staff", "staff") {
		t.Fatal("err hr_manager should have hr_staff and staff.")
	}
	if !e.HasAllRole("hr_manager", "staff") {
		t.Fatal("err hr_manager should have hr_staff and staff.")
	}
	if !e.HasAllRole("ceo", "hr_staff") {
		t.Fatal("ceo should have indirect role 'hr_staff")
	}
	if e.HasAllRole("ceo", "cfo") {
		t.Fatal("ceo should NOT have role 'cfo'")
	}
	if e.HasAnyRole("ceo", "cfo", "cto") {
		t.Fatal("ceo should NOT have role 'cfo','cto'")
	}
	if !e.HasAnyRole("ceo", "cfo", "hr_staff") {
		t.Fatal("ceo should NOT have role 'cfo' but have hr_staff")
	}
}

func TestGetPerm(t *testing.T) {
	if err := e.DropPerm("select", "employee"); err != nil && err != errs.ErrPermNotExist {
		t.Fatal("error drop perm", err.Error())
	}
	if err := e.DropPerm("select", "employee"); err != errs.ErrPermNotExist {
		t.Fatal("error drop perm")
	}
	if _, exists := e.GetPerm("select", "employee", true); exists {
		t.Fatal("error get perm")
	}
	if _, exists := e.GetPerm("select", "employee", true); !exists {
		t.Fatal("error get perm, should exist")
	}
}

func TestGrantRevokePerm(t *testing.T) {
	if err := e.GrantPerm("hr_mgr", "employee", "delete", "update"); err != nil {
		t.Fatal("err grant perm")
	}
	if err := e.RevokePerm("hr_mgr", "employee", "delete"); err != nil {
		t.Fatal("err revoke perm")
	}
}

func TestDecision(t *testing.T) {
	e.DropRole("ceo")
	e.DropRole("hr_mgr")
	e.DropRole("acct_mgr")
	e.DropRole("hr_stf")
	e.DropRole("staff")
	e.DropRole("cto")
	e.DropRole("cfo")
	e.GrantRole("ceo", "hr_mgr")
	e.GrantRole("hr_mgr", "hr_stf")
	e.GrantRole("cfo", "acct_mgr")
	e.GrantRole("acct_mgr", "acct_stf")
	e.GrantPerm("hr_mgr", "employee", "update", "delete")
	e.GrantPerm("hr_stf", "employee", "select", "insert")
	e.GrantPerm("acct_mgr", "employee", "update")
	if ! e.Decision("ceo", "employee", "insert", "delete", "update", "select") {
		t.Fatal("ceo should has permission of update employee")
	}
	if ! e.Decision("hr_mgr", "employee", "select", "delete", "update", "insert") {
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
