package rbac

import (
	"github.com/shavac/go.sec/errs"
	"github.com/shavac/go.sec/resource"
)

type Perm struct {
	name     string
	resource resource.Resource
}

func NewPerm(permName string, res resource.Resource) (*Perm, error) {
	if _, exist := egn.GetPerm(permName, res.String(), true); exist {
		return &Perm{permName, res}, errs.ErrDupPerm
	} else {
		return &Perm{permName, res}, nil
	}
}

func NewGlobalPerm(permName string) (*Perm, error) {
	return NewPerm(permName, Res(""))
}

func (p *Perm) Resource() resource.Resource {
	return p.resource
}

func (p *Perm) Name() string {
	return p.name
}

func (p *Perm) Drop() error {
	return egn.DropPerm(p.Name(), p.Resource().String())
}
