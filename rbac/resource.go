package rbac

type Resource interface {
	Guid() string
	Name() string
}
