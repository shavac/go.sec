package adapter

type EntryRecord struct {
	Type      string
	SecureId  int
	Operation string
	Target    string
	Permit    bool
	Ctx       string
	RunOnce   bool
}
