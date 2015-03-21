package engine

import (
	"fmt"
	"reflect"
)

type engineInitFunc func(interface{}) (RBACProvider, error)

type engineRegistry map[string]engineInitFunc

var registry = make(engineRegistry)

func Register(conn interface{}, f engineInitFunc) {
	registry[reflect.TypeOf(conn).String()]=f
}

func Factory(conn interface{}) (RBACProvider, error) {
	if f, ok := registry[reflect.TypeOf(conn).String()]; !ok {
		return nil, fmt.Errorf("error conn type %T not registered\n", conn)
	} else {
		return f(conn)
	}
}
