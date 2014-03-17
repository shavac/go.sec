package rbac

import (
	"testing"
)

func TestAuthzInterface(t *testing.T) {
	var _ authz = &Perm{}
	var _ authz = &Role{}
}
