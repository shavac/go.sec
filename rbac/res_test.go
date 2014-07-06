package rbac

import (
	"testing"
)

func TestURLRes(t *testing.T) {
	u1, _ := NewURLRes("root", "/")
	u2, _ := NewURLRes("usr", "/usr")
	u3, _ := NewURLRes("ulib", "/usr/lib")
	u4, _ := NewURLRes("var", "/var")
	u2c, _ := NewURLRes("usr", "/usr")
	if u1.Equals(u2) {
		t.Fatal("u1 should not equal u2")
	}
	if !u1.Includes(u2, u3, u4) {
		t.Fatal("u1 should include u2 u3 u4")
	}
	if !u2c.Equals(u2) {
		t.Fatal("u2 and u2c should be equal")
	}
}
