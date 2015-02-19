package errs

import "errors"

var (
	ErrDupPerm = errors.New("Permission already exists")
	ErrDupUser = errors.New("User already exists")
	ErrDupRole = errors.New("Role already exists")
	ErrRoleNotExist = errors.New("Role does not exist")
	ErrUserNotExist = errors.New("Role does not exist")
	ErrParseRes = errors.New("Can not parse resource string")
	ErrEngine = errors.New("Engine does not return correct data")
	ErrNotGrantable = errors.New("User is not grantable")
)







