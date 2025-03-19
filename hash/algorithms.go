package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Function is a type for hashing function signatures
type Function func([]byte) []byte

// Available hash types with their respective functions
var Types = map[string]Function{
	"MD5":     MD5,
	"SHA-1":   SHA1,
	"SHA-256": SHA256,
	"bcrypt":  Bcrypt,
}

// GetHashOptions returns a list of available hash algorithm names
func GetHashOptions() []string {
	return []string{"MD5", "SHA-1", "SHA-256", "bcrypt"}
}

// MD5 implements MD5 hashing
func MD5(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

// SHA1 implements SHA-1 hashing
func SHA1(data []byte) []byte {
	hash := sha1.Sum(data)
	return hash[:]
}

// SHA256 implements SHA-256 hashing
func SHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Bcrypt implements bcrypt hashing (a slow hash)
func Bcrypt(data []byte) []byte {
	// Use a cost of 10 which is the default
	hash, err := bcrypt.GenerateFromPassword(data, 10)
	if err != nil {
		fmt.Printf("Error generating bcrypt hash: %v\n", err)
		return []byte{}
	}
	return hash
} 