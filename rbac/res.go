package rbac

import (
	"net/url"
)

type Res interface {
	URL() *url.URL
	Name() string
	Equals(Res) bool
	Includes(...Res) bool
	BelongsTo(Res) bool
}

var Tao *tao = &tao{}

//tao belongs to everything and includes everything.
type tao struct {
}

func (t *tao) URL() *url.URL {
	url, _ := url.Parse("rbac:tao")
	return url
}

func (t *tao) Name() string {
	return "rbac:tao"
}

func (t *tao) Equals(Res) bool {
	return false
}

func (t *tao) Includes(...Res) bool {
	return true
}

func (t *tao) BelongsTo(Res) bool {
	return true
}

func GetResByURL(url string) (Res, error) {
	if url == Tao.URL().String() {
		return Tao
	}
	return resProvider.GetResByURL(url)
}
