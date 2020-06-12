package openssl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

// CurrentOpenSSLDigestFunc is an alias to the key derivation function used in OpenSSL
var CurrentOpenSSLDigestFunc = DigestSHA256Sum

// DigestFunc are functions to create a key from the passphrase
type DigestFunc func([]byte) []byte

// DigestMD5Sum uses the (deprecated) pre-OpenSSL 1.1.0c MD5 digest to create the key
func DigestMD5Sum(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// DigestSHA1Sum uses SHA1 digest to create the key
func DigestSHA1Sum(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// DigestSHA256Sum uses SHA256 digest to create the key which is the default behaviour since OpenSSL 1.1.0c
func DigestSHA256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// CredsGenerator are functions to derive a key and iv from a password and a salt
type CredsGenerator func(password, salt []byte) (OpenSSLCreds, error)

var (
	BytesToKeyMD5    = NewBytesToKeyGenerator(DigestMD5Sum)
	BytesToKeySHA1   = NewBytesToKeyGenerator(DigestSHA1Sum)
	BytesToKeySHA256 = NewBytesToKeyGenerator(DigestSHA256Sum)
)

// openSSLEvpBytesToKey follows the OpenSSL (undocumented?) convention for extracting the key and IV from passphrase.
// It uses the EVP_BytesToKey() method which is basically:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatentaion, until there are sufficient bytes available
// 48 bytes since we're expecting to handle AES-256, 32bytes for a key and 16bytes for the IV
func NewBytesToKeyGenerator(hashFunc DigestFunc) CredsGenerator {
	return func(password, salt []byte) (OpenSSLCreds, error) {
		var m []byte
		prev := []byte{}
		for len(m) < 48 {
			a := make([]byte, len(prev)+len(password)+len(salt))
			copy(a, prev)
			copy(a[len(prev):], password)
			copy(a[len(prev)+len(password):], salt)

			prev = hashFunc(a)
			m = append(m, prev...)
		}
		return OpenSSLCreds{Key: m[:32], IV: m[32:48]}, nil
	}
}

func NewPBKDF2Generator(hashFunc DigestFunc) CredsGenerator {
	return func(password, salt []byte) (OpenSSLCreds, error) {
		// FIXME: Implement something useful
		return OpenSSLCreds{}, nil
	}
}
