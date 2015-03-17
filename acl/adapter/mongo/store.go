package mongo

import (
	"github.com/shavac/go.sec/acl/adapter"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"fmt"
)

type store struct {
	name string
	*mgo.Database
}

func init() {
	adapter.Register(new(mgo.Database), Init)
}

func Init(conn interface{}, aclName string) (adapter.ACLAdapter, error) {
	if db,ok := conn.(*mgo.Database); !ok {
		return nil, fmt.Errorf("need type *mgo.Database, got %T\n", conn)
	} else {
		return &store{aclName, db}, nil
	}
}

func InitWithDBName(url, dbName, aclName string) (adapter.ACLAdapter, error) {
	sess, err := mgo.Dial(url)
	if err != nil {
		return nil, err
	}
	sess.SetMode(mgo.Monotonic, true)
	db := sess.DB(dbName)
	return Init(db, aclName)
}

func (s store) Clear() error {
	if _, err := s.C(s.name).RemoveAll(&bson.M{}); err != nil {
		return err
	}
	return nil
}

func (s store) SaveEntry(order int, er adapter.EntryRecord) error {
	return s.C(s.name).Insert(&adapter.OrderedRecord{order, er})
}

func (s store) AllRecord() (<-chan adapter.EntryRecord, error) {
	iter := s.C(s.name).Find(bson.M{}).Sort("order").Iter()
	result := adapter.OrderedRecord{}
	out := make(chan adapter.EntryRecord)
	go func() {
		for iter.Next(&result) {
			out <- result.Record
		}
		close(out)
	}()
	return out, nil
}
