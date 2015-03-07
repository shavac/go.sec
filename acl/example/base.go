package main

import (
	. "github.com/shavac/go.sec/acl"
	"github.com/shavac/go.sec/acl/adapter/json"
)

func main() {
	adpt:= json.Init("/tmp/1.json")
	adpt2:= json.Init("/tmp/2.json")
	acl := NewACL(false)
	acl.AddEntry(EntryFactory("BASE", 0, "read", "book", true, "", false))
	acl.AddEntry(EntryFactory("BASE", 0, "write","book",true,"", false))
	acl.SaveTo(adpt)
	acl2 := NewACL(false)
	acl2.LoadFrom(adpt)
	acl2.SaveTo(adpt2)
	println(acl.Decide(0, "read","book",""))
	println(acl2.Decide(0, "read","book",""))
}
