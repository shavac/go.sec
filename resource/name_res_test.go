package resource

import (
	"testing"
)

func TestNameRes(t *testing.T) {
	n1, _ := ParseNameRes("1", "n1")
	n2, _ := ParseNameRes("2", "n2")
	n1a, _ := ParseNameRes("3", "n1")
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
