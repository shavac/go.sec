package mongo

import (
	"fmt"
	"github.com/shavac/go.sec/errs"
	"github.com/shavac/go.sec/resource"
	. "github.com/shavac/go.sec/rbac/engine"
	"gopkg.in/mgo.v2"
	. "gopkg.in/mgo.v2/bson"
	"sort"
)

var (
	SeqCol = struct {
		name string
		row  struct {
			Id  int
			Scn int
		}
	}{name: "seq"}
	RoleCol = struct {
		name string
		row  struct {
			Id             int
			RoleName       string `bson:"_id,omitempty"`
			RoleType       int
			RoleDesc       string
			GrantedRoles   []string
			GrantedPermIds []int
			IndirectGrants struct {
				ChgNum  int
				Roles   []string
				PermIds []int
			}
		}
	}{name: "role"}
	PermCol = struct {
		name string
		row  struct {
			Id   int
			Perm struct {
				PermName string
				Resource struct {
					Type   string
					String string
				}
			} `bson:"_id,omitempty"`
		}
	}{name: "perm"}
)

type mongoEngine struct {
	*mgo.Database
}

func init() {
	Register(new(mgo.Database), Init)
}

func Init(conn interface{}) (RBACProvider, error) {
	if db, ok := conn.(*mgo.Database); !ok {
		return nil, fmt.Errorf("need type *mgo.Database, got %T\n", conn)
	} else {
		cnt, _ := db.C(`system.namespaces`).Find(M{`name`: fmt.Sprintf(`%s.%s`, db.Name, SeqCol.name)}).Count()
		if cnt == 0 {
			if err := db.C(SeqCol.name).Insert(SeqCol.row); err != nil {
				return nil, err
			}
		}
		return &mongoEngine{db}, nil
	}
}

func (e *mongoEngine) currentId() int {
	e.C(SeqCol.name).Find(M{}).One(&SeqCol.row)
	return SeqCol.row.Id
}

func (e *mongoEngine) nextId() int {
	e.C(SeqCol.name).Find(M{}).Apply(mgo.Change{
		Update: M{
			"$inc": M{"id": 1},
		},
		ReturnNew: true,
	}, &SeqCol.row)
	return SeqCol.row.Id
}

func (e *mongoEngine) currentScn() int {
	e.C(SeqCol.name).Find(M{}).One(&SeqCol.row)
	return SeqCol.row.Scn
}

func (e *mongoEngine) IncScn() int {
	e.C(SeqCol.name).Find(M{}).Apply(mgo.Change{
		Update: M{
			"$inc": M{"scn": 1},
		},
		ReturnNew: true,
	}, &SeqCol.row)
	return SeqCol.row.Scn
}

func (e *mongoEngine) findRoleByName(roleName string) (*mgo.Query, error) {
	q := e.C(RoleCol.name).FindId(roleName)
	if n, err := q.Count(); err != nil {
		return q, err
	} else if n == 0 {
		return q, errs.ErrRoleNotExist
	}
	return q, nil
}

func (e *mongoEngine) GetRole(roleName string, create bool) (int, int, bool) {
	var exist bool
	q, _ := e.findRoleByName(roleName)
	n, err := q.Count()
	if err != nil {
		panic("error getting role")
	}
	switch n {
	case 1:
		exist = true
		q.One(&RoleCol.row)
	case 0:
		exist = false
		RoleCol.row.RoleName = roleName
		RoleCol.row.RoleType = ROLE
		if create {
			RoleCol.row.Id = e.nextId()
			e.C(RoleCol.name).Insert(RoleCol.row)
			e.IncScn()
		}
	default:
		panic("Duplicate roles")
	}
	return RoleCol.row.Id, RoleCol.row.RoleType, exist
}

func (e *mongoEngine) SetRoleType(roleName string, rbacType int) error {
	q, err := e.findRoleByName(roleName)
	if err != nil {
		return err
	}
	_, err = q.Apply(mgo.Change{
		Update: M{"$set": M{"roletype": rbacType}},
	}, nil)
	return err
}

func (e *mongoEngine) DropRole(roleName string) error {
	if err := e.C(RoleCol.name).Update(
		M{},
		M{"$pullAll": M{"grantedroles": []string{roleName}}},
	); err != nil {
		return err
	}
	//below delete role
	if err := e.C(RoleCol.name).Remove(M{"_id": roleName}); err != nil {
		return err
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) GrantRole(grantee string, grants ...string) error {
	chg:= M{"$addToSet": M{"grantedroles": M{"$each": grants}}}
	if cInfo, err := e.C(RoleCol.name).UpsertId(grantee, chg); err != nil {
		println(cInfo.Updated)
		return err
	}
	for _, g := range grants {
		e.GetRole(g, true)
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) RevokeRole(revokee string, revoked ...string) error {
	if _, _, exist := e.GetRole(revokee, false); !exist {
		return errs.ErrRoleNotExist
	}
	if err := e.C(RoleCol.name).Update(
		M{"_id": revokee},
		M{"$pullAll": M{"grantedroles": revoked}},
	); err != nil {
		return err
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) GetPerm(permName, resString string, create bool) (id int, exist bool) {
	q := e.C(PermCol.name).Find(M{"_id.permname": permName, "_id.resource.string": resString})
	if n, _ := q.Count(); n == 1 {
		q.One(&PermCol.row)
		return PermCol.row.Id, true
	} else {
	}
	PermCol.row.Id = e.nextId()
	PermCol.row.Perm.PermName = permName
	PermCol.row.Perm.Resource.String = resString
	if err := e.C(PermCol.name).Insert(PermCol.row); err != nil {
		return -1, false
	}
	e.IncScn()
	return PermCol.row.Id, false
}

func (e *mongoEngine) DropPerm(permName, resString string) error {
	PermCol.row.Perm.PermName = permName
	PermCol.row.Perm.Resource.String = resString
	q := e.C(PermCol.name).Find(M{"_id.permname": permName, "_id.resource.string": resString})
	if n, _ := q.Count(); n == 1 {
		_, err := q.Apply(mgo.Change{Remove: true}, &PermCol.row)
		e.IncScn()
		return err
	} else if n == 0 {
		return errs.ErrPermNotExist
	}
	return nil
}

func (e *mongoEngine) GrantPerm(roleName, resString string, perms ...string) error {
	ids, _ := e.getPermIds(resString, perms, true)
	chg := M{"$addToSet": M{"grantedpermids": M{"$each": ids}}}
	if _, err := e.C(RoleCol.name).UpsertId(roleName, chg); err != nil {
		return err
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) RevokePerm(roleName string, resString string, perms ...string) error {
	if _, _, exist := e.GetRole(roleName, false); !exist {
		return errs.ErrRoleNotExist
	}
	ids, _ := e.getPermIds(resString, perms, false)
	if err := e.C(RoleCol.name).Update(
		M{"_id": roleName},
		M{"$pullAll": M{"grantedpermids": ids}},
	); err != nil {
		return err
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) SetDesc(id int, desc string) bool {
	return false
}

func (e *mongoEngine) GetDesc(id int) string {
	return ""
}

func (e *mongoEngine) buildRoleCache(roleName string) error {
	q, err := e.findRoleByName(roleName)
	if err != nil {
		return err
	}
	q.One(&RoleCol.row)
	if RoleCol.row.IndirectGrants.ChgNum == e.currentScn() {
		return nil
	}
	var indRoles sort.StringSlice
	var indPermIds sort.IntSlice
	var indPermIdMap = make(map[int]bool)
	f := func(r string) bool {
		indRoles = append(indRoles, r)
		rr, _ := e.findRoleByName(r)
		row := RoleCol.row
		rr.One(&row)
		for _, id := range row.GrantedPermIds {
			indPermIdMap[id] = true
		}
		return false
	}
	visited = make(map[string]bool)
	e.dfs(roleName, f)
	indRoles.Sort()
	for k, _ := range indPermIdMap {
		indPermIds = append(indPermIds, k)
	}
	RoleCol.row.IndirectGrants.Roles = indRoles
	RoleCol.row.IndirectGrants.PermIds = indPermIds
	RoleCol.row.IndirectGrants.ChgNum = e.currentScn()
	if err := e.C(RoleCol.name).UpdateId(
		roleName,
		M{"$set": M{"indirectgrants": RoleCol.row.IndirectGrants}},
	); err != nil {
		return err
	}
	return nil
}

func (e *mongoEngine) grantedRoles(roleName string) []string {
	e.C(RoleCol.name).Find(M{"_id": roleName}).One(&RoleCol.row)
	return RoleCol.row.GrantedRoles
}

func (e *mongoEngine) HasAllRole(roleName string, hasRoleNames ...string) bool {
	e.buildRoleCache(roleName)
	dRoles := e.C(RoleCol.name).Find(M{"_id": roleName, "indirectgrants.roles": M{"$all": hasRoleNames}})
	if n, _ := dRoles.Count(); n == 0 {
		return false
	} else {
		return true
	}
}

func (e *mongoEngine) HasAnyRole(roleName string, hasRoleNames ...string) bool {
	e.buildRoleCache(roleName)
	dRoles := e.C(RoleCol.name).Find(M{"_id": roleName, "indirectgrants.roles": M{"$in": hasRoleNames}})
	if n, _ := dRoles.Count(); n == 0 {
		return false
	} else {
		return true
	}
}

func (e *mongoEngine) getPermIds(resString string, perms []string, create bool) (sort.IntSlice, error) {
	var ids sort.IntSlice
	var err error
	for _, p := range perms {
		id, exist := e.GetPerm(p, resString, create)
		if ! exist {
			err=errs.ErrPermNotExist
		}
		ids=append(ids, id)
	}
	ids.Sort()
	return ids, err
}

func (e *mongoEngine) Decision(roleName string, res string, perms ...string) bool {
	permids, err := e.getPermIds(res, perms, false)
	if err == errs.ErrPermNotExist {
		return false
	}
	e.buildRoleCache(roleName)
	q := e.C(RoleCol.name).Find(M{"_id": roleName, "indirectgrants.permids": M{"$all": permids}})
	if n, err := q.Count(); err != nil || n != 1 {
		return false
	} else {
		return true
	}
}

func (e *mongoEngine) DecisionEx(roleName string, res string, perms ...string) bool {
	if e.Decision(roleName, res, perms...) {
		return true
	}
	if err :=e.C(RoleCol.name).FindId(roleName).One(&RoleCol.row); err != nil {
		return  false
	}
	permids := RoleCol.row.IndirectGrants.PermIds
	r1, err := resource.Parse(res)
	if err != nil {
		panic(err)
	}
	pm := new(map[string][]resource.Resource)
	for _, pid := range permids {
		if err := e.C(PermCol.name).Find(M{"id": pid}).One(&PermCol.row); err != nil {
			continue
		}
		r2, err := resource.Parse(PermCol.row.Perm.Resource.String)
		if err != nil {
			continue
		}
		pm[PermCol.row.Perm.PermName]=append(pm[PermCol.row.Perm.PermName], r2)
	}
	for perm := range perms {
		found :=false
		for r3 := range pm[perm] {
			if r3.Contains(r1) {
				found=true
				break
			}
		}
		if ! found {
			return false
		}
	}
	return true
}
