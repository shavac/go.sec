package resource

type Resource interface {
	Name() string
	Equals(Resource) bool
	Contains(...Resource) bool
	String() string
}

//first argument is resource string, second is resource name
func Parse(s ...string) (Resource, error) {
	return parsers.Parse(s...)
}

func RegisterParseFunc(pf ...ParseFunc) {
	parsers.Insert(pf...)
}

func ClearAllParser() {
	parsers = &resParser{}
}
