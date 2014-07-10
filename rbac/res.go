package rbac

import (
	. "github.com/shavac/go.sec/rbac/res"
)

func init() {
	ResParser.Append(ParseURLRes)
}

func NewRes(name, resString string) (Res, error) {
	engine.ResAlias(name, resString)
	return ParseRes(name, resString)
}
