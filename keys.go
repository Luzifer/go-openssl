package openssl

import (
	"crypto/md5"  //#nosec G501 -- Used for OpenSSL compatibility in old KDF
	"crypto/sha1" //#nosec G505 -- Used for OpenSSL compatibility in old KDF
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// DefaultPBKDF2Iterations specifies the number of iterations to use
// in PBKDF2 key generation. This is taken from the `openssl enc`
// commands default.
//
// Taken from OpenSSL v3.1.2:
// `openssl enc --help |& grep -A1 iter`
const DefaultPBKDF2Iterations = 10000

const (
	opensslKeyLength = 32
	opensslIVLength  = 16
)

// CredsGenerator are functions to derive a key and iv from a password and a salt
type CredsGenerator func(password, salt []byte) (Creds, error)

var (
	// BytesToKeyMD5 utilizes MD5 key-derivation (`-md md5`)
	BytesToKeyMD5 = NewBytesToKeyGenerator(md5.New)
	// BytesToKeySHA1 utilizes SHA1 key-derivation (`-md sha1`)
	BytesToKeySHA1 = NewBytesToKeyGenerator(sha1.New)
	// BytesToKeySHA256 utilizes SHA256 key-derivation (`-md sha256`)
	BytesToKeySHA256 = NewBytesToKeyGenerator(sha256.New)
	// BytesToKeySHA384 utilizes SHA384 key-derivation (`-md sha384`)
	BytesToKeySHA384 = NewBytesToKeyGenerator(sha512.New384)
	// BytesToKeySHA512 utilizes SHA512 key-derivation (`-md sha512`)
	BytesToKeySHA512 = NewBytesToKeyGenerator(sha512.New)
	// PBKDF2MD5 utilizes PBKDF2 key derivation with MD5 hashing (`-pbkdf2 -md md5`)
	PBKDF2MD5 = NewPBKDF2Generator(md5.New, DefaultPBKDF2Iterations)
	// PBKDF2SHA1 utilizes PBKDF2 key derivation with SHA1 hashing (`-pbkdf2 -md sha1`)
	PBKDF2SHA1 = NewPBKDF2Generator(sha1.New, DefaultPBKDF2Iterations)
	// PBKDF2SHA256 utilizes PBKDF2 key derivation with SHA256 hashing (`-pbkdf2 -md sha256`)
	PBKDF2SHA256 = NewPBKDF2Generator(sha256.New, DefaultPBKDF2Iterations)
	// PBKDF2SHA384 utilizes PBKDF2 key derivation with SHA384 hashing (`-pbkdf2 -md sha384`)
	PBKDF2SHA384 = NewPBKDF2Generator(sha512.New384, DefaultPBKDF2Iterations)
	// PBKDF2SHA512 utilizes PBKDF2 key derivation with SHA512 hashing (`-pbkdf2 -md sha512`)
	PBKDF2SHA512 = NewPBKDF2Generator(sha512.New, DefaultPBKDF2Iterations)
)

// NewBytesToKeyGenerator implements the openSSLEvpBytesToKey key
// derivation functions described in the OpenSSL code as follows:
//
// openSSLEvpBytesToKey follows the OpenSSL (undocumented?) convention for extracting the key and IV from passphrase.
// It uses the EVP_BytesToKey() method which is basically:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatentaion, until there are sufficient bytes available
// 48 bytes since we're expecting to handle AES-256, 32bytes for a key and 16bytes for the IV
func NewBytesToKeyGenerator(hashFunc func() hash.Hash) CredsGenerator {
	df := func(in []byte) []byte {
		h := hashFunc()
		if _, err := h.Write(in); err != nil {
			panic(fmt.Errorf("writing to hash: %w", err))
		}
		return h.Sum(nil)
	}

	return func(password, salt []byte) (Creds, error) {
		var m []byte
		prev := []byte{}
		for len(m) < opensslKeyLength+opensslIVLength {
			a := make([]byte, len(prev)+len(password)+len(salt))
			copy(a, prev)
			copy(a[len(prev):], password)
			copy(a[len(prev)+len(password):], salt)

			prev = df(a)
			m = append(m, prev...)
		}
		return Creds{Key: m[:opensslKeyLength], IV: m[opensslKeyLength : opensslKeyLength+opensslIVLength]}, nil
	}
}

// NewPBKDF2Generator implements a credential generator compatible
// with the OpenSSL `-pbkdf2` parameter
func NewPBKDF2Generator(hashFunc func() hash.Hash, iterations int) CredsGenerator {
	return func(password, salt []byte) (Creds, error) {
		m := pbkdf2.Key(password, salt, iterations, opensslKeyLength+opensslIVLength, hashFunc)
		return Creds{Key: m[:opensslKeyLength], IV: m[opensslKeyLength : opensslKeyLength+opensslIVLength]}, nil
	}
}
