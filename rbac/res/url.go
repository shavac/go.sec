package res

import (
	"net/url"
	"strings"
)

type URLRes struct {
	name string
	*url.URL
}

func ParseURLRes(name string, rawurl string) (Res, error) {
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

