package rbac

import(
	. "github.com/shavac/go.sec/rbac/res"
)

func RBACDecision(roleName, resString string, ops ...string) bool {
	res, err := ParseRes("", resString)
	if err != nil {
		return false
	}
	pms := GetPermsByRole(roleName)
	filtedPerms := []Perm{}
	for _, perm := range pms {
		if perm.Res().Includes(res) {
			filtedPerms = append(filtedPerms, perm)
		}
	}
	for _, op := range ops {
		for _, p := range filtedPerms {
			if p.Op() == op {
				goto next
			}
		}
		return false
	next:
	}
	return true
}

