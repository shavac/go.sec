package res

import (
	"testing"
)

func TestURLRes(t *testing.T) {
	u1, _ := ParseURLRes("root", "/")
	u2, _ := ParseURLRes("usr", "/usr")
	u3, _ := ParseURLRes("ulib", "/usr/lib")
	u4, _ := ParseURLRes("var", "/var")
	u2c, _ := ParseURLRes("usr", "/usr")
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
