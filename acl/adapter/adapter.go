package adapter

type ACLAdapter interface {
	SaveEntry(order int, er EntryRecord) error
	AllRecord() (<-chan EntryRecord, error)
	Clear() error
}
