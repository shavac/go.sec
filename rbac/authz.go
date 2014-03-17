// Package rbac provides rbac apis. Engines shall implemented in other packages.
package rbac

const (
	IDENT = iota
	ROLE
	PERM
)

//authz includes role, permission
//authzcode must be unique

type authz interface {
	Type() int
	Name() string
	AuthzCode() string
	Equals(authz) bool
	Contains(authz) bool
	BelongsTo(authz) bool
}
