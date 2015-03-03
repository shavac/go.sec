package errs

import "errors"

var (
	ErrDupPerm          = errors.New("Permission already exists")
	ErrDupUser          = errors.New("User already exists")
	ErrDupRole          = errors.New("Role already exists")
	ErrRoleNotExist     = errors.New("Role does not exist")
	ErrUserNotGrantable = errors.New("User are not grantable")
	ErrPermNotExist     = errors.New("Permission does not exist")
	ErrParseRes         = errors.New("Can not parse resource string")
	ErrEngine           = errors.New("Engine does not return correct data")
)
