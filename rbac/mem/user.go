package mem

import (
	_ "github.com/shavac/go.sec/rbac"
)

//User is a identity implementation

type User struct {
	Username        string
	CryptedPassword string
}

func (u *User) Name() string {
	return u.Username
}

func (u *User) Id() string {
	return u.Name()
}

func (u *User) GrantRole(rolename string) error {
	return RoleProvider.IdentGrantRole(u.Name(), rolename)
}

func (u *User) RevokeRole(rolename string) error {
	return RoleProvider.IdentRevokeRole(u.Name(), rolename)
}

func (u *User) HasRole(rolename string) bool {
	return RoleProvider.IdentHasRole(u.Name(), rolename)
}

func (u *User) HasPerm(permname string) bool {
	return RoleProvider.IdentHasPerm(u.Name(), permname)
}

func (u *User) HasAllRoles(rolenames ...string) bool {
	return RoleProvider.IdentHasAllRoles(u.Name(), rolenames...)
}

func (u *User) HasAnyRole(rolenames ...string) bool {
	return RoleProvider.IdentHasAnyRole(u.Name(), rolenames...)
}

func (u *User) HasAllPerms(permnames ...string) bool {
	return RoleProvider.IdentHasAllPerms(u.Name(), permnames...)
}

func (u *User) HasAnyPerm(permnames ...string) bool {
	return RoleProvider.IdentHasAnyPerm(u.Name(), permnames...)
}

func NewUser(username, password string) (*User, error) {
	return IdentProvider.(UserContainer).NewUser(username, password)
}
