package resource

import (
	"testing"
)

func TestParseRes(t *testing.T) {
	u1, _ := Parse("/", "")
	u2, _ := Parse("/usr", "")
	u3, _ := Parse("/usr/lib", "")
	u4, _ := Parse("/var", "")
	u2c, _ := Parse("/usr", "")
	n1, _ := Parse("1", "n1")
	n2, _ := Parse("2", "n2")
	n1a, _ := Parse("3", "n1")
	if  _, ok := u1.(*URLRes); ! ok {
		t.Fatal("n1 should has type *URLRes")
	}
	if  _, ok := n1.(*NameRes); ! ok {
		t.Fatal("n1 should has type *NameRes")
	}
	if u1.Equals(u2) {
		t.Fatal("u1 should not equal u2")
	}
	if !u1.Contains(u2, u3, u4) {
		t.Fatal("u1 should contain u2 u3 u4")
	}
	if !u2c.Equals(u2) {
		t.Fatal("u2 and u2c should be equal")
	}
	if n1.Equals(n2) {
		t.Fatal("n1 should not equal n2")
	}
	if n1.Contains(n2) {
		t.Fatal("n1 should not Contain n2")
	}
	if !n1.Equals(n1a) {
		t.Fatal("n1 should equal n1a")
	}
	if !n1.Contains(n1a) {
		t.Fatal("n1 should contain n1a")
	}
}
