package resource

var parsers = &resParser{}

func init() {
	RegisterParseFunc(ParseNameRes, ParseURLRes)
}
