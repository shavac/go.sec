package mem

func init() {
	IdentProvider = NewUserContainer()
	RoleProvider = NewRoleContainer()
	PermProvider = NewPermContainer()
	RBACProvider = NewRBACContainer(RoleProvider, PermProvider)
}
