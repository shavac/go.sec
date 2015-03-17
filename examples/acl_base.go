package main

import (
	. "github.com/shavac/go.sec/acl"
	"github.com/shavac/go.sec/acl/adapter/json"
)

func main() {
	adpt,_:= json.InitWithFileName("/tmp/1.json")
	adpt2,_:= json.InitWithFileName("/tmp/2.json")
	acl := NewACL()
	acl.Append("BASE", 0, "read", "book", true, "", false)
	acl.Append("BASE", 0, "write","book",true,"", false)
	if err := acl.SaveTo(adpt) ; err != nil {
		println(err.Error())
		return
	}
	acl2 := NewACL()
	acl2.LoadFrom(adpt)
	acl2.SaveTo(adpt2)
	println(acl.Decide(0, "read","book","")==PERMIT)
	println(acl2.Decide(0, "read","book",""))
}
