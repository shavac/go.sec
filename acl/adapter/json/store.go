package json

import (
	"encoding/json"
	"github.com/shavac/go.sec/acl/adapter"
	"os"
	"sort"
)

type OrderedEntry struct {
	Order  int
	Record adapter.EntryRecord
}

type store struct {
	fileName string
	Policy   bool
	Entries  []OrderedEntry
}

func Init(fname string) adapter.ACLAdapter {
	return &store{fileName: fname}
}

func (s *store) Len() int {
	return len(s.Entries)
}

func (s *store) Less(i, j int) bool {
	return s.Entries[i].Order < s.Entries[j].Order
}

func (s *store) Swap(i, j int) { s.Entries[i], s.Entries[j] = s.Entries[j], s.Entries[i] }

func (s *store) SaveEntry(order int, er adapter.EntryRecord) error {
	s.Entries = append(s.Entries, OrderedEntry{order, er})
	sort.Sort(s)
	return s.SaveToFile()
}

func (s *store) SaveToFile() error {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		return err
	}
	jsonFile, err :=os.Create(s.fileName)
	defer jsonFile.Close()
	if err != nil {
		return err
	}
	jsonFile.Truncate(0)
	jsonFile.Write(b)
	return nil
}

func (s *store) GetPolicy() bool {
	return s.Policy
}

func (s *store) SetPolicy(p bool) error {
	s.Policy=p
	return s.SaveToFile()
}

func (s *store) LoadFromFile() error {
	jsonFile, err:= os.Open(s.fileName)
	defer jsonFile.Close()
	if err != nil {
		return err
	}
	fst, err := jsonFile.Stat()
	if err != nil {
		return err
	}
	b := make([]byte, fst.Size())
	if _, err := jsonFile.Read(b); err != nil {
		return err
	}
	if err := json.Unmarshal(b, s); err != nil {
		println(err.Error())
		return err
	}
	return nil
}

func (s *store) AllRecord() (<-chan adapter.EntryRecord, error) {
	if err:= s.LoadFromFile(); err != nil {
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



