package main

import (
	"github.com/shavac/go.sec/acl"
	"github.com/shavac/go.sec/acl/adapter"
	_ "github.com/shavac/go.sec/acl/adapter/json"
	_ "github.com/shavac/go.sec/acl/adapter/mongo"
	"os"
	"gopkg.in/mgo.v2"
	"time"
)

func main() {
	jsf, err := os.Create("/tmp/a.json")
	if err != nil {
		println(err.Error())
		os.Exit(-1)
	}
	adp1, err := adapter.Factory(jsf,"acl1")
	if err != nil {
		println(err.Error())
	}
	sess, err := mgo.Dial("localhost")
	if err != nil {
		println(err.Error())
	}
	sess.SetMode(mgo.Monotonic, true)
	adp2, err := adapter.Factory(sess.DB("acl"), "acl2")
	if err != nil {
		println(err.Error())
	}
	acl1 := acl.NewACL()
	acl2 := acl.NewACL()
	acl1.LoadFrom(adp1)
	if err := acl1.Append("TIMERANGE",0, "connect","host1",true,"20150317000000-20150318000000",true); err != nil {
		println(err.Error())
	}
	acl1.SaveTo(adp1)
	if err := acl1.SaveTo(adp2); err != nil {
		println(err.Error())
	}
	if err:= acl2.LoadFrom(adp2); err != nil {
		println(err.Error())
	}
	println(acl1.Decide(0, "connect","host1",time.Now())==acl.PERMIT)
	println(acl1.Decide(0, "connect","host1",time.Now())==acl.PERMIT)
	println(acl2.Decide(0, "connect","host1",time.Now())==acl.PERMIT)
	println(acl2.Decide(0, "connect","host1",time.Now())==acl.UNDETERMINED)
}
