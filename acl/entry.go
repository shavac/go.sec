package acl

import (
	"github.com/shavac/go.sec/acl/adapter"
	"fmt"
)

type Entry interface {
	Key() adapter.RecordKey
	Match(target string, d interface{}) (bool, error)
	Decide() bool
	Record() adapter.EntryRecord
}

type EntryConstructFunc func(secureId int, operation, target string, permit bool, ctx string, runOnce bool) (Entry, error)

var EntryRegistry = make(map[string]EntryConstructFunc)

func EntryFactory(eType string, secureId int, operation, target string, permit bool, ctx string, runOnce bool) (Entry, error) {
	if f, ok := EntryRegistry[eType]; !ok {
		return nil, fmt.Errorf("Entry type %s have not registered", eType)
	} else {
		return f(secureId, operation, target, permit, ctx, runOnce)
	}
}
















