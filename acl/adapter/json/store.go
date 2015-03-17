package json

import (
	"encoding/json"
	"fmt"
	"github.com/shavac/go.sec/acl/adapter"
	"os"
	"sort"
	"io/ioutil"
)

type store struct {
	file    *os.File
	Entries []adapter.OrderedRecord
}

func init() {
	adapter.Register(new(os.File), Init)
}

func Init(conn interface{}, aclName string) (adapter.ACLAdapter, error) {
	if f, ok := conn.(*os.File); !ok {
		return nil, fmt.Errorf("wrong argument type, need *os.File, got %T\n", conn)
	} else {
		return &store{file: f}, nil
	}
}

func InitWithFileName(fname string) (adapter.ACLAdapter, error) {
	if f, err := os.OpenFile(fname, os.O_CREATE|os.O_RDWR, 0644); err != nil {
		return nil, err
	} else {
		return Init(f, "")
	}
}

func (s *store) Len() int {
	return len(s.Entries)
}

func (s *store) Less(i, j int) bool {
	return s.Entries[i].Order < s.Entries[j].Order
}

func (s *store) Swap(i, j int) { s.Entries[i], s.Entries[j] = s.Entries[j], s.Entries[i] }

func (s *store) SaveEntry(order int, er adapter.EntryRecord) error {
	s.Entries = append(s.Entries, adapter.OrderedRecord{order, er})
	sort.Sort(s)
	return s.SaveToFile()
}

func (s *store) SaveToFile() error {
	if b, err := json.MarshalIndent(s, "", "\t") ;err != nil {
		return err
	} else {
		s.Clear()
		_, err := s.file.Write(b)
		return err
	}
}

func (s *store) Clear() error {
	s.Entries=s.Entries[:0]
	err := s.file.Truncate(0)
	return err
}

func (s *store) LoadFromFile() error {
	s.file.Seek(0, 0)
	b, err:= ioutil.ReadAll(s.file)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	return nil
}

func (s *store) AllRecord() (<-chan adapter.EntryRecord, error) {
	if err := s.LoadFromFile(); err != nil {
		return nil, err
	}
	out := make(chan adapter.EntryRecord)
	go func() {
		for _, r := range s.Entries {
			out <- r.Record
		}
		close(out)
	}()
	return out, nil
}
