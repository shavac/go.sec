package rbac

import (
	"errors"
)

var (
	ErrorIdentNotExist  = errors.New("Identity does not exist")
	ErrorRoleNotExist   = errors.New("Role does not exist")
	ErrorPermNotExist   = errors.New("Permission does not exist")
	ErrorResNotExist   = errors.New("Resource does not exist")
	ErrorDuplicateRole  = errors.New("Role already exists")
	ErrorDuplicatePerm  = errors.New("Permission already granted")
	ErrorAlreadyGranted = errors.New("Role already granted to ident")
	ErrorRoleNotGranted = errors.New("Role is not granted to ident")
)
