package rbac

import (
	. "github.com/shavac/go.sec/rbac/res"
)

type Perm struct {
	op  string
	res Res
}

func (p *Perm) RBACType() int {
	return PERM
}

func (p *Perm) Res() Res {
	return p.res
}

func (p *Perm) Op() string {
	return p.op
}

func NewPerm(res string, op string) (*Perm, error) {
	r, err := ResParser.Parse("", res)
	if err != nil {
		return nil, err
	}
	return &Perm{op, r}, nil
}

type PermSet []Perm

func (ps PermSet) RBACType() int {
	return PERMSET
}

func NewPermSet(res string, ops ...string) (PermSet, error) {
	r, err := ResParser.Parse("", res)
	if err != nil {
		return nil, err
	}
	var perms PermSet
	for _, op := range ops {
		perms = append(perms, Perm{op: op, res: r})
	}
	return perms, nil
}

func NewSysPerm(op string) (*Perm, error) {
	return NewPerm("", op)
}
