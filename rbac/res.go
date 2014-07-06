package rbac

import (
	"github.com/shavac/go.sec/rbac/errs"
	"net/url"
	"strings"
)

var (
	ResParser = &resParser{}
)

func init() {
	ResParser.Append(NewURLRes)
}

type Res interface {
	Name() string
	Equals(Res) bool
	Includes(...Res) bool
	String() string
}

type resParserFunc func(string, string) (Res, error)

type resParser struct {
	parsers []resParserFunc
}

func (rp *resParser) Append(f resParserFunc) {
	rp.parsers = append(rp.parsers, f)
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
	return nil, errs.ErrParseRes
}

type URLRes struct {
	name string
	*url.URL
}

func NewURLRes(name string, rawurl string) (Res, error) {
	resurl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	ur := &URLRes{name, resurl}
	return ur, nil
}

func (ur *URLRes) Name() string {
	if ur.name == "" {
		return ur.String()
	}
	return ur.name
}

func (ur *URLRes) Equals(res Res) bool {
	if r, ok := res.(*URLRes); ok {
		return r.name == ur.name && r.String() == ur.String()
	}
	return false
}

func (ur *URLRes) Includes(resl ...Res) bool {
	for _, res := range resl {
		if r, ok := res.(*URLRes); ok {
			switch {
			case len(r.String()) < len(ur.String()):
				return false
			case !strings.HasPrefix(r.String(), ur.String()):
				return false
			case len(r.String()) == len(ur.String()):
				continue
			case strings.HasPrefix(r.String()[len(ur.String())-1:], "/"):
				continue
			default:
				return false
			}
		}
	}
	return true
}
