package mem

import (
	"code.google.com/p/go.crypto/scrypt"
	"fmt"
)

func crypt(password string) string {
	k, err := scrypt.Key([]byte(password), []byte(SALT), 16384, 8, 1, 32)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", k)
}
