[![](https://badges.fyi/static/godoc/reference/5272B4)](https://godoc.org/github.com/Luzifer/go-openssl)
[![Go Report Card](https://goreportcard.com/badge/github.com/Luzifer/go-openssl)](https://goreportcard.com/report/github.com/Luzifer/go-openssl)
![](https://badges.fyi/github/license/Luzifer/go-openssl)
![](https://badges.fyi/github/latest-tag/Luzifer/go-openssl)
[![](https://travis-ci.org/Luzifer/go-openssl.svg?branch=master)](https://travis-ci.org/Luzifer/go-openssl)

# Luzifer / go-openssl

`go-openssl` is a small library wrapping the `crypto/aes` functions in a way the output is compatible to OpenSSL / CryptoJS. For all encryption / decryption processes AES256 is used so this library will not be able to decrypt messages generated with other than `openssl aes-256-cbc`. If you're using CryptoJS to process the data you also need to use AES256 on that side.

## OpenSSL 1.1.0c compatibility

Starting with `v2.0.0` `go-openssl` generates the encryption keys using `sha256sum` algorithm. This is the default introduced in OpenSSL 1.1.0c. When encrypting data you can choose which digest method to use and therefore also continue to use `md5sum`. When decrypting OpenSSL encrypted data `md5sum`, `sha1sum` and `sha256sum` are supported.

## Installation

```
go get github.com/Luzifer/go-openssl
```

## Usage example

The usage is quite simple as you don't need any special knowledge about OpenSSL and/or AES256:

### Encrypt

```go
import (
  "fmt"
  "github.com/Luzifer/go-openssl"
)

func main() {
  plaintext := "Hello World!"
  passphrase := "z4yH36a6zerhfE5427ZV"

  o := openssl.New()

  enc, err := o.EncryptString(passphrase, plaintext)
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
  "github.com/Luzifer/go-openssl"
)

func main() {
  opensslEncrypted := "U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="
  passphrase := "z4yH36a6zerhfE5427ZV"

  o := openssl.New()

  dec, err := o.DecryptString(passphrase, opensslEncrypted)
  if err != nil {
    fmt.Printf("An error occurred: %s\n", err)
  }

  fmt.Printf("Decrypted text: %s\n", string(dec))
}
```

## Testing

To execute the tests for this library you need to be on a system having `/bin/bash` and `openssl` available as the compatibility of the output is tested directly against the `openssl` binary. The library itself should be usable on all operating systems supported by Go and `crypto/aes`.
