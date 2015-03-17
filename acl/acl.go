package acl

import (
	"sync"
	"github.com/shavac/go.sec/acl/adapter"
)



type ACL struct {
	entryCollection map[adapter.RecordKey][]Entry
	sync.RWMutex
}

func NewACL() *ACL {
	return &ACL{entryCollection: make(map[adapter.RecordKey][]Entry)}
}

func (acl *ACL) InsEntry(e Entry) {
	acl.Lock()
	defer acl.Unlock()
	acl.entryCollection[e.Key()] = append([]Entry{e}, acl.entryCollection[e.Key()]...)
}

func (acl *ACL) AddEntry(e Entry) {
	acl.Lock()
	defer acl.Unlock()
	acl.entryCollection[e.Key()] = append(acl.entryCollection[e.Key()], e)
}

func (acl *ACL) Insert(eType string, secureId int, operation, target string, permit bool, ctx string, runOnce bool) error {
	e, err := EntryFactory(eType, secureId, operation, target, permit, ctx, runOnce)
	if err != nil {
		return err
	}
	acl.InsEntry(e)
	return nil
}

func (acl *ACL) Append(eType string, secureId int, operation, target string, permit bool, ctx string, runOnce bool) error {
	e, err := EntryFactory(eType, secureId, operation, target, permit, ctx, runOnce)
	if err != nil {
		return err
	}
	acl.AddEntry(e)
	return nil
}

func (acl *ACL) Decide(secureId int, operation string, target string, d interface{}) int {
	acl.RLock()
	defer acl.RUnlock()
	rk := adapter.RecordKey{secureId, operation}
	for i, e := range acl.entryCollection[rk] {
		if ok, _ := e.Match(target, d); ok {
			if e.Record().RunOnce {
				defer func() {
					acl.entryCollection[rk]=append(acl.entryCollection[rk][:i], acl.entryCollection[rk][i+1:]...)
				}()
			}
			if e.Decide() {
				return PERMIT
			} else {
				return DENY
			}
		}
	}
	return UNDETERMINED
}

func (acl *ACL) SaveTo(adpt adapter.ACLAdapter) error {
	acl.Lock()
	defer acl.Unlock()
	if err :=adpt.Clear(); err != nil {
		return err
	}
	for _, v := range acl.entryCollection {
		for i, e := range v {
			if err := adpt.SaveEntry(i, e.Record()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (acl *ACL) LoadFrom(adpt adapter.ACLAdapter) error {
	ers, err := adpt.AllRecord()
	if err != nil {
		return err
	}
	for er := range ers {
		err := acl.Append(er.Type, er.SecureId, er.Operation, er.Target, er.Permit, er.Ctx, er.RunOnce)
		if err != nil {
			return err
		}
	}
	return nil
}
