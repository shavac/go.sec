package rbac

import (
)

type Perm struct {
	op string
	res Res
}

func (p *Perm) RBACType() int {
	return PERM
}

func NewPerm(res string, ops ...string) ([]Perm, error) {
	r, err := ResParser.Parse("", res)
	if err != nil {
		return nil ,err
	}
	var perms []Perm
	for _, op := range ops {
		perms = append(perms, Perm{op: op, res: r})
	}
	return perms, nil
}

func NewSysPerm(ops ...string) ([]Perm, error) {
	return NewPerm("", ops...)
}


func (p *Perm) Res() Res {
	return p.res
}

func (p *Perm) Op() string {
	return p.op
}

