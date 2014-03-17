package rbac

type Perm struct {
	name string
	res  Res
}

func (p *Perm) Name() string {
	return p.name
}

func (p *Perm) Type() int {
	return PERM
}

func (p *Perm) AuthzCode() string {
	if p.res== nil {
		return "PERM_"+p.Name()
	}
	return "PERM_" + p.Name() + "_" + p.res.URL().String()
}

func (p *Perm) Res() Res {
	return p.res
}

func (p *Perm) Allow(resl ...Res) bool {
	if p.res== nil {
		return true
	}
	for _, res := range resl {
		if !res.BelongsTo(p.Res()) {
			return false
		}
	}
	return true
}

func (p *Perm) Equals(a authz) bool {
	return a.AuthzCode() == p.AuthzCode()
}

//permission contains no other authz
func (p *Perm) Contains(authz) bool {
	return false
}

func (p *Perm) BelongsTo(a authz) bool {
	return roleProvider.RoleContainsAuthz(a.AuthzCode(), p.AuthzCode())
}

func NewResPerm(name string, res Res) *Perm {
	roleProvider.RegisterPerm(name, res.URL().String())
	return &Perm{
		name: name,
		res:  res,
	}
}

func NewSysPerm(name string) *Perm {
	roleProvider.RegisterPerm(name)
	return &Perm{
		name: name,
		res:  nil,
	}
}

func PermsByIdentAndResUrl(identname, url string) []*Perm {
	for _, code := range roleProvider.PermsByResUrl(url) {
		println(code)
	}
	return nil
}
