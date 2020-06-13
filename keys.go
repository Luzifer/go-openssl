package openssl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

const DefaultPBKDF2Iterations = 10000

// CredsGenerator are functions to derive a key and iv from a password and a salt
type CredsGenerator func(password, salt []byte) (Creds, error)

var (
	BytesToKeyMD5    = NewBytesToKeyGenerator(md5.New)
	BytesToKeySHA1   = NewBytesToKeyGenerator(sha1.New)
	BytesToKeySHA256 = NewBytesToKeyGenerator(sha256.New)
	BytesToKeySHA384 = NewBytesToKeyGenerator(sha512.New384)
	BytesToKeySHA512 = NewBytesToKeyGenerator(sha512.New)
	PBKDF2MD5        = NewPBKDF2Generator(md5.New, DefaultPBKDF2Iterations)
	PBKDF2SHA1       = NewPBKDF2Generator(sha1.New, DefaultPBKDF2Iterations)
	PBKDF2SHA256     = NewPBKDF2Generator(sha256.New, DefaultPBKDF2Iterations)
	PBKDF2SHA384     = NewPBKDF2Generator(sha512.New384, DefaultPBKDF2Iterations)
	PBKDF2SHA512     = NewPBKDF2Generator(sha512.New, DefaultPBKDF2Iterations)
)

// openSSLEvpBytesToKey follows the OpenSSL (undocumented?) convention for extracting the key and IV from passphrase.
// It uses the EVP_BytesToKey() method which is basically:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatentaion, until there are sufficient bytes available
// 48 bytes since we're expecting to handle AES-256, 32bytes for a key and 16bytes for the IV
func NewBytesToKeyGenerator(hashFunc func() hash.Hash) CredsGenerator {
	df := func(in []byte) []byte {
		h := hashFunc()
		h.Write(in)
		return h.Sum(nil)
	}

	return func(password, salt []byte) (Creds, error) {
		var m []byte
		prev := []byte{}
		for len(m) < 48 {
			a := make([]byte, len(prev)+len(password)+len(salt))
			copy(a, prev)
			copy(a[len(prev):], password)
			copy(a[len(prev)+len(password):], salt)

			prev = df(a)
			m = append(m, prev...)
		}
		return Creds{Key: m[:32], IV: m[32:48]}, nil
	}
}

func NewPBKDF2Generator(hashFunc func() hash.Hash, iterations int) CredsGenerator {
	return func(password, salt []byte) (Creds, error) {
		m := pbkdf2.Key(password, salt, iterations, 32+16, hashFunc)
		return Creds{Key: m[:32], IV: m[32:48]}, nil
	}
}
