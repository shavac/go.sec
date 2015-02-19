package res

import (
	"github.com/shavac/go.sec/rbac/err"
)

type Res interface {
	Name() string
	Equals(Res) bool
	Includes(...Res) bool
	String() string
}

var (
	ResParser = &resParser{}
)

type resParserFunc func(string, string) (Res, error)

type resParser struct {
	parsers []resParserFunc
}

func (rp *resParser) Append(f ...resParserFunc) {
	rp.parsers = append(rp.parsers, f...)
}

func (rp *resParser) Insert(f resParserFunc) {
	rp.parsers = append([]resParserFunc{f}, rp.parsers...)
}

func (rp *resParser) Parse(name, resString string) (Res, error) {
	for _, p := range rp.parsers {
		if r, err := p(name, resString); err == nil {
			return r, nil
		}
	}
	if resString=="" {
		return nil, nil
	}
	return nil, err.ErrParseRes
}

func ParseRes(name, resString string) (Res, error) {
	return ResParser.Parse(name, resString)
}
