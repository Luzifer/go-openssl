[![](https://badges.fyi/static/godoc/reference/5272B4)](https://pkg.go.dev/github.com/Luzifer/go-openssl/v4)
[![Go Report Card](https://goreportcard.com/badge/github.com/Luzifer/go-openssl)](https://goreportcard.com/report/github.com/Luzifer/go-openssl)
![](https://badges.fyi/github/license/Luzifer/go-openssl)
![](https://badges.fyi/github/latest-tag/Luzifer/go-openssl)
[![](https://travis-ci.org/Luzifer/go-openssl.svg?branch=master)](https://travis-ci.org/Luzifer/go-openssl)

# Luzifer / go-openssl

`go-openssl` is a small library wrapping the `crypto/aes` functions in a way the output is compatible to OpenSSL / CryptoJS. For all encryption / decryption processes AES256 is used so this library will not be able to decrypt messages generated with other than `openssl aes-256-cbc`. If you're using CryptoJS to process the data you also need to use AES256 on that side.

## Version support

For this library only the latest major version is supported. All prior major versions should no longer be used.

The versioning is following [SemVer](https://semver.org/) which means upgrading to a newer major version will break your code!

## OpenSSL compatibility

### 1.1.0c

Starting with `v2.0.0` `go-openssl` generates the encryption keys using `sha256sum` algorithm. This is the default introduced in OpenSSL 1.1.0c. When encrypting data you can choose which digest method to use and therefore also continue to use `md5sum`. When decrypting OpenSSL encrypted data `md5sum`, `sha1sum` and `sha256sum` are supported.

### 1.1.1

Starting with `v4.0.0` `go-openssl` is capable of using the PBKDF2 key derivation method for encryption. You can choose to use it by passing the corresponding `CredsGenerator`.

## Installation

```bash
# Get the latest version
go get github.com/Luzifer/go-openssl

# OR get a specific version
go get gopkg.in/Luzifer/go-openssl.v4
```

## Usage example

The usage is quite simple as you don't need any special knowledge about OpenSSL and/or AES256:

### Encrypt

```go
import (
  "fmt"
  openssl "gopkg.in/Luzifer/go-openssl.v4"
)

func main() {
  plaintext := "Hello World!"
  passphrase := "z4yH36a6zerhfE5427ZV"

  o := openssl.New()

  enc, err := o.EncryptBytes(passphrase, []byte(plaintext), PBKDF2SHA256)
  if err != nil {
    fmt.Printf("An error occurred: %s\n", err)
  }

  fmt.Printf("Encrypted text: %s\n", string(enc))
}
```

### Decrypt

```go
import (
  "fmt"
  openssl "gopkg.in/Luzifer/go-openssl.v4"
)

func main() {
  opensslEncrypted := "U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="
  passphrase := "z4yH36a6zerhfE5427ZV"

  o := openssl.New()

  dec, err := o.DecryptBytes(passphrase, []byte(opensslEncrypted), BytesToKeyMD5)
  if err != nil {
    fmt.Printf("An error occurred: %s\n", err)
  }

  fmt.Printf("Decrypted text: %s\n", string(dec))
}
```

## Testing

To execute the tests for this library you need to be on a system having `/bin/bash` and `openssl` available as the compatibility of the output is tested directly against the `openssl` binary. The library itself should be usable on all operating systems supported by Go and `crypto/aes`.
