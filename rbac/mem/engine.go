package mem

import (
	"github.com/shavac/go.sec/rbac/errs"
	"sort"
	"sync"
)

var (
	Engine *engine
)

func init() {
	Engine = &engine{}
}

type stor struct {
	id            int
	name, context string
	rbacType      int
	perms permList
}

type permStor struct {
	action   int
	resource int
}

type permList []permStor

func (pl permList) Len() int {
	return len(pl)
}

func (pl permList) Less(i, j int) bool {
	return pl[i].action < pl[j].action && pl[i].resource < pl[j].resource
}

func (pl permList) Swap(i, j int) {
	pl[i], pl[j] = pl[j], pl[i]
}

type engine struct {
	serial        int
	storage       map[int]stor
	resourceAlias map[string]int
	action        map[string]int
	perm          permList
	role          map[string]int
	roleGraph     map[string]sort.StringSlice
	sync.Mutex
}

func (e *engine) Init(string) error {
	e = &engine{
		serial:        0,
		storage:       make(map[int]stor),
		resourceAlias: make(map[string]int),
		action:        make(map[string]int),
		role:          make(map[string]int),
		roleGraph:     make(map[string]sort.StringSlice),
	}
	return nil
}

func (e *engine) GetVersion() int {
	return e.serial
}

func (e *engine) IncVersion() int {
	e.serial++
	return e.serial
}

func (e *engine) GetRole(roleName string) (bool, int, string) {
	if id, ok := e.role[roleName]; ok {
		return true, e.storage[id].rbacType, e.storage[id].context
	}
	return false, 0, ""
}

func (e *engine) SaveRole(roleName string, roleType int, desc string) bool {
	var id int
	var ok bool
	e.Lock()
	defer e.Unlock()
	if roleName=="" {
		return false
	}
	if _, ok = e.role[roleName]; ok {
		id = e.role[roleName]
	} else {
		id = e.IncVersion()
	}
	e.storage[id] = stor{id: id, name: roleName, context: desc, rbacType: roleType}
	return ok
}

func (e *engine) HasAllRole(roleName string, HasRoleNames ...string) bool {
	return false
}

func (e *engine) HasAnyRole(roleName string, HasRoleNames ...string) bool {
	return false
}

func (e *engine) GrantRole(grantee string, granted ...string) error {
	for _, roleName := range granted {
		_, ok := e.role[roleName]
		if ! ok {
			return errs.ErrRoleNotExist
		}
		e.roleGraph[grantee] = append(e.roleGraph[grantee], roleName)
	}
	return nil
}

func (e *engine) RevokeRole(revokee string, revoked ...string) error {
	for _, roleName := range revoked {
		_, ok := e.role[roleName]
		if ! ok {
			return errs.ErrRoleNotExist
		}
		for i, rn := range e.roleGraph[revokee] {
			if rn==roleName {
				e.roleGraph[revokee][i]=""
			}
		}
	}
	return nil
}

func (e *engine) GrantPerm(roleName, res string, op ...string) error {
	return nil
}

func (e *engine) RevokePerm(roleName, res string, op ...string) error {
	return nil
}

func (e *engine) GetOpsByRes(res string) []string {
	return []string{}
}

func (e *engine) GetPermsByRole(roleName string) ([]string, []string) {
	return nil, nil
}

func (e *engine) HasAllPerm(roleName, res string, ops ...string) bool {
	return false
}

func (e *engine) ResAlias(alias, resString string) bool {
	id, ok := e.resourceAlias[resString];
	if ! ok {
		id = e.IncVersion()
		e.storage[id] = stor{id: id, name: resString, rbacType: RES}
	}
	if alias == "" {
		return true
	} else if _, ok := e.resourceAlias[alias]; ok {
		return false
	} else {
		e.resourceAlias[alias]=id
	}
	return true
}

func (e *engine) Gc() {
}
