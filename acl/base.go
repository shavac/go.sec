package acl

import "github.com/shavac/go.sec/acl/adapter"

const (
	base = "BASE"
)

func init() {
	EntryRegistry[base] = NewBaseEntry
}

type BaseEntry struct {
	adapter.EntryRecord
}

func NewBaseEntry(secureId int, operation, target string, permit bool, ctx string, runOnce bool) (Entry, error) {
	return &BaseEntry{
		adapter.EntryRecord{
			RecordKey: adapter.RecordKey {
				SecureId:  secureId,
				Operation: operation,
			},
			Type:      base,
			Target:    target,
			Permit:    permit,
			Ctx:       ctx,
			RunOnce:   runOnce,
		},
	}, nil
}

func (e *BaseEntry) SecureId() int {
	return e.EntryRecord.SecureId
}

func (e *BaseEntry) Type() string {
	return base
}

func (e *BaseEntry) Match(target string, d interface{}) (bool, error) {
	return target == e.EntryRecord.Target, nil
}

func (e *BaseEntry) Decide() bool {
	return e.EntryRecord.Permit
}

func (e *BaseEntry) RunOnce() bool {
	return e.EntryRecord.RunOnce
}

func (e *BaseEntry) Key() adapter.RecordKey {
	return e.RecordKey
}

func (e *BaseEntry) Record() adapter.EntryRecord {
	return e.EntryRecord
}







