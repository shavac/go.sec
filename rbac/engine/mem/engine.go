package mem

import (
	"github.com/shavac/go.sec/errs"
	. "github.com/shavac/go.sec/rbac/engine"
	"github.com/shavac/go.sec/resource"
	"sort"
	"sync"
)

type storlet struct {
	sType    int
	sName    string
	sContent string
}

type engine struct {
	initialized bool
	serial      int
	roleMap     map[string]int
	permMap     map[string]map[string]int
	resMap      map[string]int
	storage     map[int]*storlet
	desc        map[int]string
	roleGraph   map[int]sort.IntSlice
	rolePerm    map[int]sort.IntSlice
	sync.Mutex
}

func Init() *engine {
	egn := &engine{
		initialized: true,
		serial:      0,
		roleMap:     make(map[string]int),
		permMap:     make(map[string]map[string]int),
		resMap:      make(map[string]int),
		storage:     make(map[int]*storlet),
		desc:        make(map[int]string),
		roleGraph:   make(map[int]sort.IntSlice),
		rolePerm:    make(map[int]sort.IntSlice),
	}
	return egn
}

func (e *engine) currentSerial() int {
	return e.serial
}

func (e *engine) nextSerial() int {
	e.serial++
	return e.serial
}

func (e *engine) GetRole(roleName string, create bool) (int, int, bool) {
	if id, ok := e.roleMap[roleName]; ok {
		return id, e.storage[id].sType, true
	} else if !create {
		return -1, -1, false
	} else {
		e.Lock()
		defer e.Unlock()
		nid := e.nextSerial()
		e.roleMap[roleName] = nid
		e.storage[nid] = &storlet{ROLE, roleName, ""}
		return nid, ROLE, false
	}
}

func (e *engine) SetRoleType(roleName string, rbacType int) error {
	if id, ok := e.roleMap[roleName]; ok {
		e.Lock()
		defer e.Unlock()
		e.storage[id].sType = rbacType
		return nil
	} else {
		return errs.ErrRoleNotExist
	}
}

func (e *engine) DropRole(roleName string) error {
	e.Lock()
	defer e.Unlock()
	rid, _, exist := e.GetRole(roleName, false)
	if !exist {
		return errs.ErrRoleNotExist
	}
	delete(e.roleMap, roleName)
	delete(e.roleGraph, rid)
	delete(e.storage, rid)
	for k, v := range e.roleGraph {
		if idx := v.Search(rid); idx < v.Len() && v[idx] == rid {
			e.roleGraph[k] = append(v[:idx], v[idx+1:]...)
		}
	}
	return nil
}

func (e *engine) GrantRole(grantee string, grants ...string) error {
	gid, _, _ := e.GetRole(grantee, true)
	for _, roleName := range grants {
		rid, rType, _ := e.GetRole(roleName, true)
		if rType != ROLE {
			return errs.ErrUserNotGrantable
		}
		e.roleGraph[gid] = append(e.roleGraph[gid], rid)
		e.roleGraph[gid].Sort()
	}
	return nil
}

func (e *engine) RevokeRole(revokee string, revoked ...string) error {
	eid, _, exist := e.GetRole(revokee, true)
	if !exist {
		return errs.ErrRoleNotExist
	}
	grantedRoleId := e.roleGraph[eid]
	for _, roleName := range revoked {
		if rid, _, exist := e.GetRole(roleName, false); !exist {
			return errs.ErrRoleNotExist
		} else {
			if idx := grantedRoleId.Search(rid); idx < grantedRoleId.Len() && grantedRoleId[idx] == rid {
				grantedRoleId = append(grantedRoleId[:idx], grantedRoleId[idx+1:]...)
			}
		}
	}
	e.roleGraph[eid] = grantedRoleId
	return nil
}

func (e *engine) GetPerm(permName, resString string, create bool) (id int, exist bool) {
	if id, ok := e.permMap[permName][resString]; ok {
		return id, true
	} else if !create {
		return -1, false
	} else {
		e.Lock()
		defer e.Unlock()
		id := e.nextSerial()
		if _, ok := e.permMap[permName]; !ok {
			e.permMap[permName] = make(map[string]int)
		}
		e.permMap[permName][resString] = id
		e.storage[id] = &storlet{PERM, permName, resString}
		return id, false
	}
}

func (e *engine) DropPerm(permName, resString string) error {
	if _, ok := e.permMap[permName]; !ok {
		return errs.ErrPermNotExist
	} else if id, ok := e.permMap[permName][resString]; !ok {
		return errs.ErrPermNotExist
	} else {
		e.Lock()
		defer e.Unlock()
		delete(e.permMap[permName], resString)
		delete(e.storage, id)
		for rid, permIds := range e.rolePerm {
		D:
			if i := permIds.Search(id); i < len(permIds) && permIds[i] == id { //found
				permIds = append(permIds[:i], permIds[i+1:]...)
				goto D
			}
			e.rolePerm[rid] = permIds
		}
	}
	return nil
}

func (e *engine) GrantPerm(roleName, resString string, perms ...string) error {
	rid, _, exist := e.GetRole(roleName, true)
	for _, perm := range perms {
		pid, _ := e.GetPerm(perm, resString, true)
		permIds := e.rolePerm[rid]
		if idx := permIds.Search(pid); idx >= permIds.Len() || permIds[idx] != pid {
			e.rolePerm[rid] = append(e.rolePerm[rid], pid)
			e.rolePerm[rid].Sort()
		}
	}
	if !exist {
		return errs.ErrRoleNotExist
	}
	return nil
}

func (e *engine) RevokePerm(roleName string, res string, perms ...string) error {
	rid, _, exist := e.GetRole(roleName, false)
	if !exist {
		return errs.ErrRoleNotExist
	}
	permIds := e.rolePerm[rid]
	for _, permName := range perms {
		if pid, exist := e.GetPerm(permName, res, false); exist {
		RP:
			if i := permIds.Search(pid); i < len(permIds) && permIds[i] == pid { //found
				permIds = append(permIds[:i], permIds[i+1:]...)
				goto RP
			}
		}
	}
	e.rolePerm[rid] = permIds
	return nil
}

func (e *engine) SetDesc(id int, desc string) bool {
	if _, ok := e.storage[id]; ok {
		e.desc[id] = desc
		return true
	}
	return false
}

func (e *engine) GetDesc(id int) string {
	return e.desc[id]
}

func (e *engine) HasAllRole(roleName string, hasRoleNames ...string) bool {
	rootId, _, exist := e.GetRole(roleName, false)
	if !exist {
		return false
	}
	for _, r := range hasRoleNames {
		id, _, exist := e.GetRole(r, false)
		if !exist {
			return false
		}
		f := func(nid int) bool {
			return nid == id
		}
		found := e.searchRoleGraph(rootId, f)
		if !found {
			return false
		}
	}
	return true
}

func (e *engine) HasAnyRole(roleName string, hasRoleNames ...string) bool {
	rootId, _, exist := e.GetRole(roleName, false)
	if !exist {
		return false
	}
	for _, r := range hasRoleNames {
		id, _, exist := e.GetRole(r, false)
		if !exist {
			continue
		}
		f := func(nid int) bool {
			return nid == id
		}
		found := e.searchRoleGraph(rootId, f)
		if found {
			return true
		}
	}
	return false
}

func (e *engine) searchRoleGraph(rootId int, f func(id int) bool) bool {
	visited = sort.IntSlice{}
	found = false
	DFS(e.roleGraph, rootId, f)
	return found
}

func (e *engine) Decision(roleName string, res string, perms ...string) bool {
	rootId, _, exist := e.GetRole(roleName, false)
	if !exist {
		return false
	}
	for _, p := range perms {
		pid, exist := e.GetPerm(p, res, false)
		if !exist {
			return false
		}
		f := func(rid int) bool {
			if pms, ok := e.rolePerm[rid]; !ok {
				return false
			} else if i := pms.Search(pid); i < len(pms) && pms[i] == pid {
				return true
			}
			return false
		}
		found := e.searchRoleGraph(rootId, f)
		if !found {
			return false
		}
	}
	return true
}

func (e *engine) DecisionEx(roleName string, res string, perms ...string) bool {
	rootId, _, exist := e.GetRole(roleName, false)
	if !exist {
		return false
	}
	r1, err := resource.Parse(res)
	if err != nil {
		panic(err)
	}
	for _, permName := range perms {
		f := func(rid int) bool {
			for _, pid := range e.rolePerm[rid] {
				if e.storage[pid].sName != permName {
					continue
				} else if r2, err := resource.Parse(e.storage[pid].sContent); err != nil {
					panic(err)
				} else if r2.Contains(r1) {
					return true
				}
			}
			return false
		}
		found := e.searchRoleGraph(rootId, f)
		if !found {
			return false
		}
	}
	return true
}
