package rbac

// interface for user/role/permission
const (
	USER = iota
	ROLE
	PERM
	PERMSET
	PERMX
)

type authz interface {
	RBACType() int
}

type userRole interface {
	authz
	Name() string
	Grant(...authz) error
	Revoke(...authz) error
}
