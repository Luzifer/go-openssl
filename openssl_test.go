package openssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

var testTable = []struct {
	tName    string
	tMdParam string
	tMdFunc  CredsGenerator
}{
	{"MD5", "md5", BytesToKeyMD5},
	{"SHA1", "sha1", BytesToKeySHA1},
	{"SHA256", "sha256", BytesToKeySHA256},
}

func TestBinaryEncryptToDecryptWithCustomSalt(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"
	salt := []byte("saltsalt")

	o := New()

	enc, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := o.DecryptBinaryBytes(passphrase, enc, BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at decrypt: %s", err)
	}

	if string(dec) != plaintext {
		t.Errorf("Decrypted text did not match input.")
	}
}

func TestBinaryEncryptToDecrypt(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	enc, err := o.EncryptBinaryBytes(passphrase, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := o.DecryptBinaryBytes(passphrase, enc, BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at decrypt: %s", err)
	}

	if string(dec) != plaintext {
		t.Errorf("Decrypted text did not match input.")
	}
}

func TestBinaryEncryptToOpenSSL(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			salt, err := o.GenerateSalt()
			if err != nil {
				t.Fatalf("Failed to generate salt: %v", err)
			}

			enc, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), tc.tMdFunc)
			if err != nil {
				t.Fatalf("Test errored at encrypt: %v", err)
			}

			// Need to specify /dev/stdin as file so that we can pass in binary
			// data to openssl without creating a file
			cmd := exec.Command(
				"openssl", "aes-256-cbc",
				"-d",
				"-pass", fmt.Sprintf("pass:%s", passphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			)

			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stdin = bytes.NewBuffer(enc)

			err = cmd.Run()
			if err != nil {
				t.Errorf("OpenSSL errored: %v", err)
			}

			if out.String() != plaintext {
				t.Errorf("OpenSSL output did not match input.\nOutput was: %s", out.String())
			}
		})
	}
}

func TestBinaryEncryptWithSaltShouldHaveSameOutput(t *testing.T) {
	plaintext := "outputshouldbesame"
	passphrase := "passphrasesupersecure"
	salt := []byte("saltsalt")

	o := New()

	enc1, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	enc2, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	if string(enc1) != string(enc2) {
		t.Errorf("Encrypted outputs are not same.")
	}
}

func TestDecryptBinaryFromString(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			var out bytes.Buffer

			cmd := exec.Command(
				"openssl", "aes-256-cbc",
				"-pass", fmt.Sprintf("pass:%s", passphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			)
			cmd.Stdout = &out
			cmd.Stdin = strings.NewReader(plaintext)

			if err := cmd.Run(); err != nil {
				t.Fatalf("Running openssl CLI failed: %v", err)
			}

			data, err := o.DecryptBinaryBytes(passphrase, out.Bytes(), tc.tMdFunc)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(data) != plaintext {
				t.Logf("Data: %s\nPlaintext: %s", string(data), plaintext)
				t.Errorf("Decryption output did not equal expected output.")
			}
		})
	}
}

func TestDecryptFromString(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			var out bytes.Buffer

			cmd := exec.Command(
				"openssl", "aes-256-cbc",
				"-base64",
				"-pass", fmt.Sprintf("pass:%s", passphrase),
				"-md", tc.tMdParam,
			)
			cmd.Stdout = &out
			cmd.Stdin = strings.NewReader(plaintext)

			if err := cmd.Run(); err != nil {
				t.Fatalf("Running openssl CLI failed: %v", err)
			}

			data, err := o.DecryptBytes(passphrase, out.Bytes(), tc.tMdFunc)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(data) != plaintext {
				t.Logf("Data: %s\nPlaintext: %s", string(data), plaintext)
				t.Errorf("Decryption output did not equal expected output.")
			}
		})
	}
}

func TestEncryptToDecrypt(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	enc, err := o.EncryptBytes(passphrase, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := o.DecryptBytes(passphrase, enc, BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at decrypt: %s", err)
	}

	if string(dec) != plaintext {
		t.Errorf("Decrypted text did not match input.")
	}
}

func TestEncryptToDecryptWithCustomSalt(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"
	salt := []byte("saltsalt")

	o := New()

	enc, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := o.DecryptBytes(passphrase, enc, BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at decrypt: %s", err)
	}

	if string(dec) != plaintext {
		t.Errorf("Decrypted text did not match input.")
	}
}

func TestEncryptToOpenSSL(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			o := New()

			salt, err := o.GenerateSalt()
			if err != nil {
				t.Fatalf("Failed to generate salt: %s", err)
			}

			enc, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), tc.tMdFunc)
			if err != nil {
				t.Fatalf("Test errored at encrypt (%s): %s", tc.tMdParam, err)
			}

			enc = append(enc, '\n')

			var out bytes.Buffer

			cmd := exec.Command(
				"openssl", "aes-256-cbc",
				"-base64", "-d",
				"-pass", fmt.Sprintf("pass:%s", passphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			)
			cmd.Stdout = &out
			cmd.Stdin = bytes.NewReader(enc)

			err = cmd.Run()
			if err != nil {
				t.Errorf("OpenSSL errored (%s): %s", tc.tMdParam, err)
			}

			if out.String() != plaintext {
				t.Errorf("OpenSSL output did not match input.\nOutput was (%s): %s", tc.tMdParam, out.String())
			}
		})
	}
}

func TestEncryptWithSaltShouldHaveSameOutput(t *testing.T) {
	plaintext := "outputshouldbesame"
	passphrase := "passphrasesupersecure"
	salt := []byte("saltsalt")

	o := New()

	enc1, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	enc2, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	if string(enc1) != string(enc2) {
		t.Errorf("Encrypted outputs are not same.")
	}
}

func TestGenerateSalt(t *testing.T) {
	knownSalts := [][]byte{}

	o := New()

	for i := 0; i < 1000; i++ {
		salt, err := o.GenerateSalt()
		if err != nil {
			t.Fatalf("Failed to generate salt: %s", err)
		}

		for _, ks := range knownSalts {
			if bytes.Equal(ks, salt) {
				t.Errorf("Duplicate salt detected")
			}
			knownSalts = append(knownSalts, salt)
		}
	}
}

func TestSaltValidation(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	if _, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, []byte("12345"), []byte(plaintext), BytesToKeySHA256); err != ErrInvalidSalt {
		t.Errorf("5-character salt was accepted, needs to have 8 character")
	}

	if _, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, []byte("1234567890"), []byte(plaintext), BytesToKeySHA256); err != ErrInvalidSalt {
		t.Errorf("10-character salt was accepted, needs to have 8 character")
	}

	if _, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, []byte{0xcb, 0xd5, 0x1a, 0x3, 0x84, 0xba, 0xa8, 0xc8}, []byte(plaintext), BytesToKeySHA256); err == ErrInvalidSalt {
		t.Errorf("Salt with 8 byte unprintable characters was not accepted")
	}
}

//
// Benchmarks
//

func benchmarkDecrypt(ciphertext []byte, cg CredsGenerator, b *testing.B) {
	passphrase := "z4yH36a6zerhfE5427ZV"
	o := New()

	for n := 0; n < b.N; n++ {
		o.DecryptBytes(passphrase, ciphertext, cg)
	}
}

func BenchmarkDecryptMD5(b *testing.B) {
	benchmarkDecrypt([]byte("U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="), BytesToKeyMD5, b)
}

func BenchmarkDecryptSHA1(b *testing.B) {
	benchmarkDecrypt([]byte("U2FsdGVkX1/Yy9kegseq2Ewd4UvjFYCpIEA1cltTA1Q="), BytesToKeySHA1, b)
}

func BenchmarkDecryptSHA256(b *testing.B) {
	benchmarkDecrypt([]byte("U2FsdGVkX1+O68d7BO9ibP8nB5+xtb/27IHlyjJWpl8="), BytesToKeySHA256, b)
}

func benchmarkEncrypt(plaintext string, cg CredsGenerator, b *testing.B) {
	passphrase := "z4yH36a6zerhfE5427ZV"
	o := New()
	salt, _ := o.GenerateSalt()

	for n := 0; n < b.N; n++ {
		o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), cg)
	}
}

func BenchmarkEncryptMD5(b *testing.B) {
	benchmarkEncrypt("hallowelt", BytesToKeyMD5, b)
}

func BenchmarkEncryptSHA1(b *testing.B) {
	benchmarkEncrypt("hallowelt", BytesToKeySHA1, b)
}

func BenchmarkEncryptSHA256(b *testing.B) {
	benchmarkEncrypt("hallowelt", BytesToKeySHA256, b)
}

func BenchmarkGenerateSalt(b *testing.B) {
	o := New()
	for n := 0; n < b.N; n++ {
		o.GenerateSalt()
	}
}
