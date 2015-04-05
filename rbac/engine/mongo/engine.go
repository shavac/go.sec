package mongo

import (
	"fmt"
	"github.com/shavac/go.sec/errs"
	. "github.com/shavac/go.sec/rbac/engine"
	"github.com/shavac/go.sec/resource"
	"gopkg.in/mgo.v2"
	. "gopkg.in/mgo.v2/bson"
	"sort"
)

const (
	SeqCol  = "seq"
	RoleCol = "role"
	PermCol = "perm"
	DescCol = "desc"
)

type SeqRecord struct {
	Id  int
	Scn int
}

func NewSeq() *SeqRecord {
	return &SeqRecord{}
}

type RoleRecord struct {
	Id             int
	RoleName       string `bson:"_id,omitempty"`
	RoleType       int
	RoleDesc       string
	GrantedRoles   []string
	GrantedPermIds []int
	IndirectGrants struct {
		Scn     int
		Roles   []string
		PermIds []int
	}
}

func NewRoleRecord() *RoleRecord {
	return &RoleRecord{}
}

type PermRecord struct {
	Id   int
	Perm struct {
		PermName string
		Resource struct {
			Type string
			Url  string
		}
	} `bson:"_id,omitempty"`
}

func NewPerm() *PermRecord {
	return &PermRecord{}
}

type DescRecord struct {
	Id   int `bson:"_id,omitempty"`
	Desc string
}

func NewDesc() *DescRecord {
	return &DescRecord{}
}

type mongoEngine struct {
	*mgo.Database
	Seq   *mgo.Collection
	Roles *mgo.Collection
	Perms *mgo.Collection
	Descs *mgo.Collection
}

func init() {
	Register(new(mgo.Database), Init)
}

func Init(conn interface{}) (RBACProvider, error) {
	if db, ok := conn.(*mgo.Database); !ok {
		return nil, fmt.Errorf("need type *mgo.Database, got %T\n", conn)
	} else {
		cnt, _ := db.C(`system.namespaces`).Find(M{`name`: fmt.Sprintf(`%s.%s`, db.Name, SeqCol)}).Count()
		if cnt == 0 {
			if err := db.C(SeqCol).Insert(NewSeq()); err != nil {
				return nil, err
			}
		}
		return &mongoEngine{
			Database: db,
			Seq:      db.C(SeqCol),
			Roles:    db.C(RoleCol),
			Perms:    db.C(PermCol),
			Descs:    db.C(DescCol),
		}, nil
	}
}

func (e *mongoEngine) currentId() int {
	seq := NewSeq()
	e.Seq.Find(M{}).One(seq)
	return seq.Id
}

func (e *mongoEngine) nextId() int {
	seq := NewSeq()
	e.Seq.Find(M{}).Apply(mgo.Change{
		Update: M{
			"$inc": M{"id": 1},
		},
		ReturnNew: true,
	}, seq)
	return seq.Id
}

func (e *mongoEngine) currentScn() int {
	seq := NewSeq()
	e.Seq.Find(M{}).One(seq)
	return seq.Scn
}

func (e *mongoEngine) IncScn() int {
	seq := NewSeq()
	e.Seq.Find(M{}).Apply(mgo.Change{
		Update: M{
			"$inc": M{"scn": 1},
		},
		ReturnNew: true,
	}, seq)
	return seq.Scn
}

func (e *mongoEngine) findRoleByName(roleName string) (*mgo.Query, error) {
	q := e.Roles.FindId(roleName)
	if n, err := q.Count(); err != nil {
		return q, err
	} else if n == 0 {
		return q, errs.ErrRoleNotExist
	}
	return q, nil
}

func (e *mongoEngine) GetRole(roleName string, create bool) (int, int, bool) {
	var exist bool
	role := NewRoleRecord()
	q, err := e.findRoleByName(roleName)
	if err == errs.ErrRoleNotExist {
		exist = false
		if create {
			role.Id = e.nextId()
			role.RoleName = roleName
			role.RoleType = ROLE
			e.Roles.Insert(role)
			e.IncScn()
		}
	} else if err != nil {
		panic(err.Error())
	} else {
		exist = true
		q.One(role)
	}
	return role.Id, role.RoleType, exist
}

func (e *mongoEngine) SetRoleType(roleName string, rbacType int) error {
	if err := e.Roles.UpdateId(roleName, M{"$set": M{"roletype": rbacType}}); err != nil {
		return err
	}
	return nil
}

func (e *mongoEngine) DropRole(roleName string) error {
	if _, err := e.Roles.UpdateAll(
		M{},
		M{"$pullAll": M{"grantedroles": []string{roleName}}},
	); err != nil {
		return err
	}
	//below delete role
	if err := e.Roles.RemoveId(roleName); err != nil {
		return err
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) GrantRole(grantee string, grants ...string) error {
	e.GetRole(grantee, true)
	if err := e.Roles.UpdateId(
		grantee,
		M{"$addToSet": M{"grantedroles": M{"$each": grants}}},
	); err != nil {
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
	if err := e.Roles.UpdateId(
		revokee,
		M{"$pullAll": M{"grantedroles": revoked}},
	); err != nil {
		return err
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) GetPerm(permName, res string, create bool) (id int, exist bool) {
	perm := NewPerm()
	q := e.Perms.Find(M{"_id.permname": permName, "_id.resource.url": res})
	if n, _ := q.Count(); n == 1 {
		q.One(perm)
		return perm.Id, true
	} else {
		perm.Id = e.nextId()
		perm.Perm.PermName = permName
		perm.Perm.Resource.Url = res
		if err := e.Perms.Insert(perm); err != nil {
			return -1, false
		}
		e.IncScn()
		return perm.Id, false
	}
}

func (e *mongoEngine) DropPerm(permName, res string) error {
	if cInfo, err := e.Perms.RemoveAll(M{"_id.permname": permName, "_id.resource.string": res}); err != nil {
		return err
	} else if cInfo.Removed == 0 {
		return errs.ErrPermNotExist
	} else {
		e.IncScn()
		return nil
	}
}

func (e *mongoEngine) GrantPerm(roleName, resString string, perms ...string) error {
	ids, _ := e.getPermIds(resString, perms, true)
	chg := M{"$addToSet": M{"grantedpermids": M{"$each": ids}}}
	if _, err := e.Roles.UpsertId(roleName, chg); err != nil {
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
	if err := e.Roles.UpdateId(
		roleName,
		M{"$pullAll": M{"grantedpermids": ids}},
	); err != nil {
		return err
	}
	e.IncScn()
	return nil
}

func (e *mongoEngine) SetDesc(id int, desc string) bool {
	if nr, _ := e.Roles.Find(M{"id": id}).Count(); nr == 0 {
		if np, _ := e.Perms.Find(M{"id": id}).Count(); np == 0 {
			return false
		}
	}
	if _, err := e.Descs.UpsertId(id, M{"desc": desc}); err != nil {
		panic(err)
	}
	return true
}

func (e *mongoEngine) GetDesc(id int) string {
	d := NewDesc()
	e.Descs.FindId(id).One(d)
	return d.Desc
}

func (e *mongoEngine) buildRoleCache(roleName string) error {
	role := NewRoleRecord()
	q, err := e.findRoleByName(roleName)
	if err != nil {
		return err
	}
	q.One(role)
	if role.IndirectGrants.Scn == e.currentScn() {
		return nil
	}
	var indRoles sort.StringSlice
	var indPermIds sort.IntSlice
	var indPermIdMap = make(map[int]bool)
	f := func(rn string) bool {
		r := NewRoleRecord()
		indRoles = append(indRoles, rn)
		e.Roles.FindId(rn).One(r)
		for _, id := range r.GrantedPermIds {
			indPermIdMap[id] = true
		}
		return false
	}
	visited = make(map[string]bool)
	e.dfs(roleName, f)
	indRoles.Sort()
	for pid, _ := range indPermIdMap {
		indPermIds = append(indPermIds, pid)
	}
	role.IndirectGrants.Roles = indRoles
	role.IndirectGrants.PermIds = indPermIds
	role.IndirectGrants.Scn = e.currentScn()
	if err := e.Roles.UpdateId(
		roleName,
		M{"$set": M{"indirectgrants": role.IndirectGrants}},
	); err != nil {
		return err
	}
	return nil
}

func (e *mongoEngine) grantedRoles(roleName string) []string {
	role := NewRoleRecord()
	e.C(RoleCol).FindId(roleName).One(role)
	return role.GrantedRoles
}

func (e *mongoEngine) HasAllRole(roleName string, hasRoleNames ...string) bool {
	e.buildRoleCache(roleName)
	dRoles := e.Roles.Find(M{"_id": roleName, "indirectgrants.roles": M{"$all": hasRoleNames}})
	if n, _ := dRoles.Count(); n == 0 {
		return false
	} else {
		return true
	}
}

func (e *mongoEngine) HasAnyRole(roleName string, hasRoleNames ...string) bool {
	e.buildRoleCache(roleName)
	dRoles := e.Roles.Find(M{"_id": roleName, "indirectgrants.roles": M{"$in": hasRoleNames}})
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
		if !exist {
			err = errs.ErrPermNotExist
		}
		ids = append(ids, id)
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
	q := e.Roles.Find(M{"_id": roleName, "indirectgrants.permids": M{"$all": permids}})
	if n, err := q.Count(); err != nil || n != 1 {
		return false
	} else {
		return true
	}
}

func (e *mongoEngine) DecisionEx(roleName string, res string, perms ...string) bool {
	if permids, err := e.getPermIds(res, perms, false); err == nil {
		q := e.Roles.Find(M{"_id": roleName, "indirectgrants.permids": M{"$all": permids}})
		if n, err := q.Count(); err == nil && n == 1 {
			return true
		}
	}
	e.buildRoleCache(roleName)
	role := NewRoleRecord()
	if err := e.Roles.FindId(roleName).One(role); err != nil {
		return false
	}
	permids := role.IndirectGrants.PermIds
	r1, err := resource.Parse(res)
	if err != nil {
		panic(err)
	}
	pm := make(map[string][]resource.Resource)
	for _, pid := range permids {
		perm := NewPerm()
		if err := e.Perms.Find(M{"id": pid}).One(perm); err != nil {
			continue
		}
		r2, err := resource.Parse(perm.Perm.Resource.Url)
		if err != nil {
			continue
		}
		pm[perm.Perm.PermName] = append(pm[perm.Perm.PermName], r2)
	}
	for _, p := range perms {
		found := false
		for _, r3 := range pm[p] {
			if r3.Contains(r1) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
