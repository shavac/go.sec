package mem

type MemResource struct {
	name string
}

func (mr *MemResource) Guid() string {
	return mr.name
}

func (mr *MemResource) Name() string {
	return mr.name
}
