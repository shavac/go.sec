package mongo

var visited map[string]bool
var found bool

func (e *mongoEngine) dfs(roleName string, f func(string) bool) {
	if found {
		return
	}
	if visited[roleName] {
		return
	} else {
		visited[roleName] = true
	}
	if f(roleName) {
		found = true
		return
	}
	for _, r := range e.grantedRoles(roleName) {
		e.dfs(r, f)
	}
	return
}
