package mem

import (
	"github.com/shavac/go.sec/rbac"
	"sort"
)

var (
	SALT = "memrbac"
	IdentProvider rbac.IdentProvider
	RoleProvider rbac.RoleProvider
	PermProvider rbac.PermProvider
	RBACProvider rbac.RBACProvider
)

type UserContainer map[string]*User //implement IdentProvider

func NewUserContainer() UserContainer {
	return make(map[string]*User)
}

func (uc UserContainer) Init() {
}

func (uc UserContainer) NewUser(username, password string) (*User, error) {
	uc[username] = &User{
		Username:        username,
		CryptedPassword: crypt(password),
	}
	return uc[username], nil
}

func (uc UserContainer) GetIdentByName(name string) (rbac.Identity, error) {
	if u, ok := uc[name]; ok {
		return u, nil
	}
	return nil, rbac.ErrorIdentNotExist
}

type UserRoleMap map[string]map[string]*rbac.Role

func NewUserRoleMap() UserRoleMap {
	return make(map[string]map[string]*rbac.Role)
}

type RoleContainer struct {
	roles        map[string]*rbac.Role           //contains all roles
	roleGraph    map[string]sort.StringSlice //contains role to role relationship
	rolePermMap  map[string]sort.StringSlice //map[rolename][]permname
	identRoleMap map[string]sort.StringSlice //map[identname][]rolename
}

func NewRoleContainer() *RoleContainer {
	return &RoleContainer{
		roles:        make(map[string]string),
		roleGraph:    make(map[string]sort.StringSlice),
		rolePermMap:  make(map[string]sort.StringSlice),
		identRoleMap: make(map[string]sort.StringSlice),
	}
}

func (rc *RoleContainer) CreateRole(rolename string, desc string) (*rbac.Role, error) {
	if rc.GetRoleByName(rolename) != nil {
		return nil, rbac.ErrorDuplicateRole
	}
	rc.roles[rolename] = desc
	r := rbac.MakeRole(rolename, rc)
	return r, nil
}

func (rc *RoleContainer) DropRole(rolename string) error {
	if _, ok := rc.roles[rolename]; ok {
		delete(rc.roles, rolename)
		return nil
	}
	return rbac.ErrorRoleNotExist
}

func (rc *RoleContainer) RoleDesc(rolename string) (string, error) {
	if desc, ok := rc.roles[rolename]; ok {
		return desc, nil
	}
	return "", rbac.ErrorRoleNotExist
}

func (rc *RoleContainer) SetRoleDesc(rolename, desc string) error {
	if desc, ok := rc.roles[rolename]; ok {
		rc.roles[rolename] = desc
		return nil
	}
	return rbac.ErrorRoleNotExist
}

func (rc *RoleContainer) GetRoleByName(rolename string) *rbac.Role {
	if _, ok := rc.roles[rolename]; ok {
		return rbac.MakeRole(rolename, rc)
	}
	return nil
}

func (rc *RoleContainer) AllRoleNames() []string {
	var rns []string
	for rn, _ := range rc.roles {
		rns = append(rns, rn)
	}
	return rns
}

func (rc *RoleContainer) Init() {
}

func (rc *RoleContainer) IdentGrantRole(identname, rolename string) error {
	if rc.identRoleMap[identname].Search(rolename)!=rc.identRoleMap[identname].Len() {
		return rbac.ErrorAlreadyGranted
	}
	rc.identRoleMap[identname] = append(rc.identRoleMap[identname], rolename)
	rc.identRoleMap[identname].Sort()
	return nil
}

func (rc *RoleContainer) IdentRevokeRole(identname, rolename string) error {
	rs := rc.identRoleMap[identname]
	idx := rs.Search(rolename)
	if idx==rs.Len() {
		return rbac.ErrorRoleNotGranted
	}
	rc.identRoleMap[identname]=append(rs[0:idx], rs[idx+1:]...)
	return nil
}

func (rc *RoleContainer) IdentHasAllPerms(identname string, permnames ...string) bool {
	perms := append(rc.identRoleMap[identname], rc.indirectedRoles(identname)...)
	for _, p := range permnames {
		if perms.Search(p) == perms.Len() {
			return false
		}
	}
	return true
}

func (rc *RoleContainer) IdentHasAnyPerm(identname string, permnames ...string) bool {
	perms := append(rc.identRoleMap[identname], rc.indirectedRoles(identname)...)
	for _, p := range permnames {
		if perms.Search(p) != perms.Len() {
			return true
		}
	}
	return false
}

func (rc *RoleContainer) IdentHasPerm(identname string, permname string) bool {
	drs := rc.RolesByIdent(identname)
	for _, r := range append(drs, rc.indirectedRoles(identname)...) {
		if s:= rc.PermsByRole(r); s.Search(permname) != s.Len() {
			return true
		}
	}
	return false
}

func (rc *RoleContainer) IdentHasAllRoles(identname string, rolenames ...string) bool {
	for _, r := range rolenames {
		if ! rc.IdentHasRole(identname, r) {
			return false
		}
	}
	return true
}

func (rc *RoleContainer) IdentHasAnyRole(identname string, rolenames ...string) bool {
	for _, r := range rolenames {
		if  rc.IdentHasRole(identname, r) {
			return true
		}
	}
	return false
}

func (rc *RoleContainer) IdentHasRole(identname, rolename string) bool {
	// directly granted
	if rs, ok := rc.identRoleMap[identname]; ok && rs.Search(rolename)!=rs.Len(){
		return true
	}
	// indirectly granted
	idrs := rc.indirectedRoles(identname)
	if idrs.Search(rolename)!=idrs.Len() {
		return true
	}
	return false
}

func (rc *RoleContainer) indirectedRoles(identname string) sort.StringSlice {
	drs := rc.identRoleMap[identname] //directly granted roles
	var irs sort.StringSlice       //indirectly granted roles
	var dfs func(string)
	dfs=func(rolename string) {
		irs = append(irs, rolename)
		irs.Sort()
		for  _, rn := range rc.roleGraph[rolename] {
			if irs.Search(rn) != irs.Len() {
				break
			}
			dfs(rn)
		}
	}
	for _, dr := range drs {
		dfs(dr)
	}
	return irs
}

func (rc *RoleContainer) PermsByRole(rolename string) sort.StringSlice {
	return rc.rolePermMap[rolename]
}

func (rc *RoleContainer) RolesByIdent(identname string) sort.StringSlice {
	return rc.identRoleMap[identname]
}

func (rc *RoleContainer) RoleGrantPerm(rolename string, permname string) error {
	rc.rolePermMap[rolename]=append(rc.rolePermMap[rolename], permname)
	rc.rolePermMap[rolename].Sort()
	return nil
}

func (rc *RoleContainer) RoleRevokePerm(rolename string, permname string) error {
	idx := rc.rolePermMap[rolename].Search(permname)
	if idx == rc.rolePermMap[rolename].Len() {
		return rbac.ErrorPermNotExist
	}
	rc.rolePermMap[rolename] = append(rc.rolePermMap[rolename][:idx], rc.rolePermMap[rolename][idx+1:]...)
	return nil
}

func (rc *RoleContainer) RoleGrantRole(target string, from string) error {
	if _, ok := rc.roles[target]; ! ok{
		return rbac.ErrorRoleNotExist
	}
	if _, ok := rc.roles[from]; ! ok {
		return rbac.ErrorRoleNotExist
	}
	rc.roleGraph[target]=append(rc.roleGraph[target], from)
	rc.roleGraph[target].Sort()
	return nil
}

func (rc *RoleContainer) RoleRevokeRole(target string, from string) error {
	if _, ok := rc.roles[target]; ! ok{
		return rbac.ErrorRoleNotExist
	}
	if _, ok := rc.roles[from]; ! ok {
		return rbac.ErrorRoleNotExist
	}
	idx := rc.roleGraph[target].Search(from)
	if idx == rc.roleGraph[target].Len() {
		return rbac.ErrorRoleNotGranted
	}
	rc.roleGraph[target]=append(rc.roleGraph[target][:idx], rc.roleGraph[target][idx+1:]...)
	return nil
}

type PermContainer struct { //PermProvider implementation
	permMap map[string]rbac.Permission
}

func NewPermContainer() *PermContainer {
	return &PermContainer{
		permMap: make(map[string]rbac.Permission),
	}
}

func (pc *PermContainer) Init() {
}

func (pc *PermContainer) SavePerm(perm rbac.Permission) error {
	pc.permMap[perm.Name()] = perm
	return nil
}

func (pc *PermContainer) DelPermByName(permname string) error {
	if _, ok := pc.permMap[permname]; ok {
		delete(pc.permMap, permname)
		return nil
	}
	return rbac.ErrorPermNotExist
}

func (pc *PermContainer) GetPermByName(permname string) rbac.Permission {
	return pc.permMap[permname]
}

func (pc *PermContainer) PermsByResGuid(resguid string) []*rbac.ResourcePermission {
	var rv []*rbac.ResourcePermission
	for _, p := range pc.permMap {
		if rp, ok := p.(*rbac.ResourcePermission); ok && rp.Res().Guid() == resguid {
			rv = append(rv, rp)
		}
	}
	return rv
}

type RBACContainer struct {
	*RoleContainer
	*PermContainer
}

func NewRBACContainer(rc rbac.RoleProvider, pc rbac.PermProvider) *RBACContainer{
	return &RBACContainer {
		rc.(*RoleContainer),
		pc.(*PermContainer),
	}
}

func (rbc *RBACContainer) PermsByIdentAndResGuid(identname, resguid string) bool {
	rs := append(rbc.RoleContainer.RolesByIdent(identname), rbc.indirectedRoles(identname)...)
	var ps sort.StringSlice
	for _, r:= range rs {
		pbrs := rbc.PermsByRole(r)
		for _,pbr := range pbrs {
			if rbc.GetPermByName(pbr).Type() == rbac.RESPERM {
				ps =append(ps, pbr)
			}
		}
	}
	return false
}
