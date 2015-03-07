package acl

import (
	"sync"
	"github.com/shavac/go.sec/acl/adapter"
)

type ACL struct {
	policy          bool
	entryCollection map[int][]Entry
	sync.RWMutex
}

func NewACL(policy bool) *ACL {
	return &ACL{policy: policy, entryCollection: make(map[int][]Entry)}
}

func (acl *ACL) InsEntry(e Entry) {
	acl.Lock()
	defer acl.Unlock()
	acl.entryCollection[e.SecureId()] = append([]Entry{e}, acl.entryCollection[e.SecureId()]...)
}

func (acl *ACL) AddEntry(e Entry) {
	acl.Lock()
	defer acl.Unlock()
	acl.entryCollection[e.SecureId()] = append(acl.entryCollection[e.SecureId()], e)
}

func (acl *ACL) Decide(secureId int, operation string, target string, dString string) bool {
	acl.RLock()
	defer acl.RUnlock()
	for _, e := range acl.entryCollection[secureId] {
		if e.Match(secureId, operation, target) {
			return e.Decide(dString)
		}
	}
	return acl.policy
}

func (acl *ACL) SaveTo(adpt adapter.ACLAdapter) error {
	acl.Lock()
	defer acl.Unlock()
	for _, v := range acl.entryCollection {
		for i, e := range v {
			if err := adpt.SaveEntry(i, e.Record()); err != nil {
				return err
			}
		}
	}
	adpt.SetPolicy(acl.policy)
	return nil
}

func (acl *ACL) LoadFrom(adpt adapter.ACLAdapter) error {
	acl.Lock()
	defer acl.Unlock()
	ers, err := adpt.AllRecord()
	if err != nil {
		return err
	}
	for er := range ers {
		acl.entryCollection[er.SecureId] = append(acl.entryCollection[er.SecureId], EntryFactory(er.Type, er.SecureId, er.Operation, er.Target, er.Permit, er.Ctx, er.RunOnce))
	}
	acl.policy = adpt.GetPolicy()
	return nil
}





