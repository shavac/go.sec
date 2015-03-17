package main

import (
	. "github.com/shavac/go.sec/acl"
	"github.com/shavac/go.sec/acl/adapter/mongo"
	"github.com/shavac/go.sec/acl/adapter/json"
	"time"
)

func main() {
	adpt, err := mongo.InitWithDBName("localhost","acl","acl1")
	adpt.Clear()
	//defer adpt.Clear()
	adpt2, err := json.InitWithFileName("/tmp/v2")
	//adpt2.Clear()
	if err != nil {
		println(err.Error())
		return
	}
	acl := NewACL()
	if err := acl.Append("TIMERANGE", 0, "connect","host1",true, "20150307000000-20150308000000", false); err != nil {
		println(err.Error())
	}
	acl.Append("TIMERANGE", 0, "connect","host1",true, "20150308000000-20150309000000", false)
	acl.Append("TIMERANGE", 0, "connect","host1",false, "00000308000000-20150309000000", false)
	acl.SaveTo(adpt)
	acl2 := NewACL()
	acl2.LoadFrom(adpt)
	if err := acl2.SaveTo(adpt2); err != nil {
		println(err.Error())
	}
	println(acl.Decide(0, "connect","host1",time.Now())==UNDETERMINED)
	println(acl2.Decide(0, "connect","host1",time.Now())==UNDETERMINED)
}
