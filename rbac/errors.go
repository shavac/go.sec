package rbac

import (
	"errors"
)

var (
	ErrorIdentNotExist = errors.New("Identity does not exist")
	ErrorRoleNotExist = errors.New("Role does not exist")
	ErrorPermNotExist = errors.New("Permission does not exist")
	ErrorDuplicateRole = errors.New("Role already exists")
	ErrorDuplicatePerm = errors.New("Permission already granted")
)
