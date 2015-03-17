package adapter

type RecordKey struct {
	SecureId int
	Operation string
}

type EntryRecord struct {
	RecordKey
	Type      string
	Target    string
	Permit    bool
	Ctx       string
	RunOnce   bool
}

type OrderedRecord struct {
	Order  int
	Record EntryRecord
}
