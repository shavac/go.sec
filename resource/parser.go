package resource

import (
	"github.com/shavac/go.sec/errs"
)

type (
	ParseFunc func(resString, name string) (Resource, error)
	//Hidden resource parser list
	resParser struct {
		parsers []ParseFunc
	}
)

func (rp *resParser) Append(f ...ParseFunc) {
	rp.parsers = append(rp.parsers, f...)
}

func (rp *resParser) Insert(f ...ParseFunc) {
	rp.parsers = append(f, rp.parsers...)
}

//first argument is resource string, second is resource name
func (rp *resParser) Parse(s ...string) (Resource, error) {
	resString, name := s[0], ""
	if len(s) == 2 {
		name = s[1]
	} else if len(s) > 2 {
		return nil, errs.ErrParseRes
	}
	for _, p := range rp.parsers {
		if r, err := p(resString, name); err == nil {
			return r, nil
		}
	}
	return nil, errs.ErrParseRes
}

func (rp *resParser) AsName(name string) (Resource, error) {
	return &NameRes{name}, nil
}
