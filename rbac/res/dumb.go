package res

type DumbRes struct {
	name string
}


func (dr *DumbRes) Name() string {
	return dr.name
}

func (dr *DumbRes) Equals(res Res) bool {
	return res.Name() == dr.Name()
}

func (dr *DumbRes) Includes(res ...Res) bool {
	for _, r := range res {
		if r.Name() != dr.Name() {
			return false
		}
	}
	return true
}

func (dr *DumbRes) String() string {
	return dr.Name()
}

















