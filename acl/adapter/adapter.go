package adapter

type ACLAdapter interface {
	SaveEntry(order int, er EntryRecord) error
	AllRecord() (<-chan EntryRecord, error)
	GetPolicy() bool
	SetPolicy(bool) error
}
