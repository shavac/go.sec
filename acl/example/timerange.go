package main

import (
	. "github.com/shavac/go.sec/acl"
	"github.com/shavac/go.sec/acl/adapter/json"
	"time"
)

func main() {
	adpt:= json.Init("/tmp/tr.json")
	acl := NewACL(false)
	if err := acl.Append("TIMERANGE", 0, "connect","host1",true, "20150307000000-20150308000000", false); err != nil {
		println(err.Error())
	}
	acl.Append("TIMERANGE", 0, "connect","host1",true, "20150308000000-20150309000000", false)
	acl.Insert("TIMERANGE", 0, "connect","host1",false, "00000308000000-20150309000000", false)
	acl.SaveTo(adpt)
	println(acl.Decide(0, "connect","host1",time.Now()))
}




