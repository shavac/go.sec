package adapter

import (
	"fmt"
	"reflect"
)

type adapterInitFunc func(interface{}, string) (ACLAdapter, error)

type adapterRegistry map[string]adapterInitFunc

var registry = make(adapterRegistry)

func Register(conn interface{}, f adapterInitFunc) {
	registry[reflect.TypeOf(conn).String()] = f
}

func Factory(conn interface{}, aclName string) (ACLAdapter, error) {
	if f, ok := registry[reflect.TypeOf(conn).String()]; !ok {
		return nil, fmt.Errorf("error adapter type %T not registered\n", conn)
	} else {
		return f(conn, aclName)
	}
}
