package rbac

import (
	"github.com/shavac/go.sec/resource"
)

func Res(resString string) resource.Resource {
	res, _ := resource.Parse(resString, "")
	return res
}
