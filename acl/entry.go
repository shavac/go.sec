package acl

import "github.com/shavac/go.sec/acl/adapter"

type Entry interface {
	SecureId() int
	Match(secureId int, operation string, target string) bool
	Decide(dString string) bool
	Record() adapter.EntryRecord
}

type EntryConstructFunc func(secureId int, operation, target string, permit bool, ctx string, runOnce bool) Entry

var EntryRegistry = make(map[string]EntryConstructFunc)

func EntryFactory(eType string, secureId int, operation, target string, permit bool, ctx string, runOnce bool) Entry {
	if f, ok := EntryRegistry[eType]; !ok {
		return nil
	} else {
		return f(secureId, operation, target, permit, ctx, runOnce)
	}
}
