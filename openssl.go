package openssl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// CurrentOpenSSLDigestFunc is an alias to the key derivation function used in OpenSSL
var CurrentOpenSSLDigestFunc = DigestSHA256Sum

// ErrInvalidSalt is returned when a salt with a length of != 8 byte is passed
var ErrInvalidSalt = errors.New("Salt needs to have exactly 8 byte")

// OpenSSL is a helper to generate OpenSSL compatible encryption
// with autmatic IV derivation and storage. As long as the key is known all
// data can also get decrypted using OpenSSL CLI.
// Code from http://dequeue.blogspot.de/2014/11/decrypting-something-encrypted-with.html
type OpenSSL struct {
	openSSLSaltHeader string
}

type openSSLCreds struct {
	key []byte
	iv  []byte
}

// New instanciates and initializes a new OpenSSL encrypter
func New() *OpenSSL {
	return &OpenSSL{
		openSSLSaltHeader: "Salted__", // OpenSSL salt is always this string + 8 bytes of actual salt
	}
}

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

// DecryptBytes takes a slice of bytes with base64 encoded, encrypted data to decrypt
// and a key-derivation function. The key-derivation function must match the function
// used to encrypt the data. (In OpenSSL the value of the `-md` parameter.)
//
// You should not just try to loop the digest functions as this will cause a race
// condition and you will not be able to decrypt your data properly.
func (o OpenSSL) DecryptBytes(passphrase string, encryptedBase64Data []byte, kdf DigestFunc) ([]byte, error) {
	data := make([]byte, base64.StdEncoding.DecodedLen(len(encryptedBase64Data)))
	n, err := base64.StdEncoding.Decode(data, encryptedBase64Data)
	if err != nil {
		return nil, fmt.Errorf("Could not decode data: %s", err)
	}

	// Truncate to real message length
	data = data[0:n]

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("Data is too short")
	}
	saltHeader := data[:aes.BlockSize]
	if string(saltHeader[:8]) != o.openSSLSaltHeader {
		return nil, fmt.Errorf("Does not appear to have been encrypted with OpenSSL, salt header missing")
	}
	salt := saltHeader[8:]

	creds, err := o.extractOpenSSLCreds([]byte(passphrase), salt, kdf)
	if err != nil {
		return nil, err
	}
	return o.decrypt(creds.key, creds.iv, data)
}

func (o OpenSSL) decrypt(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad blocksize(%v), aes.BlockSize = %v", len(data), aes.BlockSize)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(data[aes.BlockSize:], data[aes.BlockSize:])
	out, err := o.pkcs7Unpad(data[aes.BlockSize:], aes.BlockSize)
	if out == nil {
		return nil, err
	}
	return out, nil
}

// EncryptBytes encrypts a slice of bytes in a manner compatible to OpenSSL encryption
// functions using AES-256-CBC as encryption algorithm. This function generates
// a random salt on every execution.
func (o OpenSSL) EncryptBytes(passphrase string, plainData []byte, kdf DigestFunc) ([]byte, error) {
	salt, err := o.GenerateSalt()
	if err != nil {
		return nil, err
	}

	return o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, plainData, kdf)
}

// EncryptBytesWithSaltAndDigestFunc encrypts a slice of bytes in a manner compatible to OpenSSL
// encryption functions using AES-256-CBC as encryption algorithm. The salt
// needs to be passed in here which ensures the same result on every execution
// on cost of a much weaker encryption as with EncryptString.
//
// The salt passed into this function needs to have exactly 8 byte.
//
// The hash function corresponds to the `-md` parameter of OpenSSL. For OpenSSL pre-1.1.0c
// DigestMD5Sum was the default, since then it is DigestSHA256Sum.
//
// If you don't have a good reason to use this, please don't! For more information
// see this: https://en.wikipedia.org/wiki/Salt_(cryptography)#Common_mistakes
func (o OpenSSL) EncryptBytesWithSaltAndDigestFunc(passphrase string, salt, plainData []byte, hashFunc DigestFunc) ([]byte, error) {
	if len(salt) != 8 {
		return nil, ErrInvalidSalt
	}

	data := make([]byte, len(plainData)+aes.BlockSize)
	copy(data[0:], o.openSSLSaltHeader)
	copy(data[8:], salt)
	copy(data[aes.BlockSize:], plainData)

	creds, err := o.extractOpenSSLCreds([]byte(passphrase), salt, hashFunc)
	if err != nil {
		return nil, err
	}

	enc, err := o.encrypt(creds.key, creds.iv, data)
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(enc)), nil
}

func (o OpenSSL) encrypt(key, iv, data []byte) ([]byte, error) {
	padded, err := o.pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded[aes.BlockSize:], padded[aes.BlockSize:])

	return padded, nil
}

// openSSLEvpBytesToKey follows the OpenSSL (undocumented?) convention for extracting the key and IV from passphrase.
// It uses the EVP_BytesToKey() method which is basically:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatentaion, until there are sufficient bytes available
// 48 bytes since we're expecting to handle AES-256, 32bytes for a key and 16bytes for the IV
func (o OpenSSL) extractOpenSSLCreds(password, salt []byte, hashFunc DigestFunc) (openSSLCreds, error) {
	var m []byte
	prev := []byte{}
	for len(m) < 48 {
		prev = o.hash(prev, password, salt, hashFunc)
		m = append(m, prev...)
	}
	return openSSLCreds{key: m[:32], iv: m[32:48]}, nil
}

func (o OpenSSL) hash(prev, password, salt []byte, hashFunc DigestFunc) []byte {
	a := make([]byte, len(prev)+len(password)+len(salt))
	copy(a, prev)
	copy(a[len(prev):], password)
	copy(a[len(prev)+len(password):], salt)
	return hashFunc(a)
}

// GenerateSalt generates a random 8 byte salt
func (o OpenSSL) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 8) // Generate an 8 byte salt
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}

// MustGenerateSalt is a wrapper around GenerateSalt which will panic on an error.
// This allows you to use this function as a parameter to EncryptBytesWithSaltAndDigestFunc
func (o OpenSSL) MustGenerateSalt() []byte {
	s, err := o.GenerateSalt()
	if err != nil {
		panic(err)
	}
	return s
}

// pkcs7Pad appends padding.
func (o OpenSSL) pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// pkcs7Unpad returns slice of the original data without padding.
func (o OpenSSL) pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padlen], nil
}
