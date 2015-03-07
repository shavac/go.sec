package acl

import "github.com/shavac/go.sec/acl/adapter"

func init() {
	EntryRegistry["BASE"] = NewBaseEntry
}

type BaseEntry struct {
	adapter.EntryRecord
}

func NewBaseEntry(secureId int, operation, target string, permit bool, ctx string, runOnce bool) Entry {
	return &BaseEntry{
		adapter.EntryRecord{
			Type:      "BASE",
			SecureId:  secureId,
			Operation: operation,
			Target:    target,
			Permit:    permit,
			Ctx:       ctx,
			RunOnce:   runOnce,
		},
	}
}

func (e *BaseEntry) SecureId() int {
	return e.EntryRecord.SecureId
}

func (e *BaseEntry) Type() string {
	return "BASE"
}

func (e *BaseEntry) Match(secureId int, operation string, target string) bool {
	return secureId == e.EntryRecord.SecureId && operation == e.EntryRecord.Operation && target == e.EntryRecord.Target
}

func (e *BaseEntry) Decide(s string) bool {
	return e.EntryRecord.Permit
}

func (e *BaseEntry) RunOnce() bool {
	return e.EntryRecord.RunOnce
}

func (e *BaseEntry) Record() adapter.EntryRecord {
	return e.EntryRecord
}


