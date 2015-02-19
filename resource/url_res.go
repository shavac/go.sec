package resource

import (
	"net/url"
	"strings"
)

type URLRes struct {
	name string
	*url.URL
}

func ParseURLRes(rawurl, name string) (Resource, error) {
	resurl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if name=="" {
		name=rawurl
	}
	newURLRes := &URLRes{name, resurl}
	return newURLRes, nil
}

func (ur *URLRes) Name() string {
	if ur.name == "" {
		return ur.String()
	}
	return ur.name
}

func (ur *URLRes) Equals(resource Resource) bool {
	if r, ok := resource.(*URLRes); ok {
		return r.name == ur.name && r.String() == ur.String()
	}
	return false
}

func (ur *URLRes) Contains(resl ...Resource) bool {
	for _, resource := range resl {
		if r, ok := resource.(*URLRes); ok {
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
