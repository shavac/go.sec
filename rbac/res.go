package rbac

import (
	. "github.com/shavac/go.sec/rbac/res"
)

func init() {
	ResParser.Append(ParseURLRes)
}

