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
	resurl, err := url.Parse(strings.TrimSpace(rawurl))
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
			urs:=strings.TrimRight(ur.String(),"/")
			rs:=strings.TrimRight(r.String(),"/")
			if!strings.HasPrefix(rs, urs) {
				return false
			}
		}
	}
	return true
}




