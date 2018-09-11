package openssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"
)

func TestDecryptFromStringMD5(t *testing.T) {
	// > echo -n "hallowelt" | openssl aes-256-cbc -pass pass:z4yH36a6zerhfE5427ZV -md md5 -a -salt
	// U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU=

	opensslEncrypted := "U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	data, err := o.DecryptString(passphrase, opensslEncrypted)

	if err != nil {
		t.Fatalf("Test errored: %s", err)
	}

	if string(data) != "hallowelt" {
		t.Errorf("Decryption output did not equal expected output.")
	}
}

func TestDecryptFromStringSHA1(t *testing.T) {
	// > echo -n "hallowelt" | openssl aes-256-cbc -pass pass:z4yH36a6zerhfE5427ZV -md sha1 -a -salt
	// U2FsdGVkX1/Yy9kegseq2Ewd4UvjFYCpIEA1cltTA1Q=

	opensslEncrypted := "U2FsdGVkX1/Yy9kegseq2Ewd4UvjFYCpIEA1cltTA1Q="
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	data, err := o.DecryptString(passphrase, opensslEncrypted)

	if err != nil {
		t.Fatalf("Test errored: %s", err)
	}

	if string(data) != "hallowelt" {
		t.Errorf("Decryption output did not equal expected output.")
	}
}

func TestDecryptFromStringSHA256(t *testing.T) {
	// > echo -n "hallowelt" | openssl aes-256-cbc -pass pass:z4yH36a6zerhfE5427ZV -md sha256 -a -salt
	// U2FsdGVkX1+O68d7BO9ibP8nB5+xtb/27IHlyjJWpl8=

	opensslEncrypted := "U2FsdGVkX1+O68d7BO9ibP8nB5+xtb/27IHlyjJWpl8="
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	data, err := o.DecryptString(passphrase, opensslEncrypted)

	if err != nil {
		t.Fatalf("Test errored: %s", err)
	}

	if string(data) != "hallowelt" {
		t.Errorf("Decryption output did not equal expected output.")
	}
}

func TestEncryptToDecrypt(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	enc, err := o.EncryptString(passphrase, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := o.DecryptString(passphrase, string(enc))
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

	enc, err := o.EncryptStringWithSalt(passphrase, salt, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	dec, err := o.DecryptString(passphrase, string(enc))
	if err != nil {
		t.Fatalf("Test errored at decrypt: %s", err)
	}

	if string(dec) != plaintext {
		t.Errorf("Decrypted text did not match input.")
	}
}

func TestEncryptWithSaltShouldHaveSameOutput(t *testing.T) {
	plaintext := "outputshouldbesame"
	passphrase := "passphrasesupersecure"
	salt := []byte("saltsalt")

	o := New()

	enc1, err := o.EncryptStringWithSalt(passphrase, salt, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	enc2, err := o.EncryptStringWithSalt(passphrase, salt, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	if string(enc1) != string(enc2) {
		t.Errorf("Encrypted outputs are not same.")
	}
}

func TestEncryptToOpenSSL(t *testing.T) {
	plaintext := "hallowelt"
	passphrase := "z4yH36a6zerhfE5427ZV"

	matrix := map[string]DigestFunc{
		"md5":    DigestMD5Sum,
		"sha1":   DigestSHA1Sum,
		"sha256": DigestSHA256Sum,
	}

	for mdParam, hashFunc := range matrix {
		o := New()

		salt, err := o.GenerateSalt()
		if err != nil {
			t.Fatalf("Failed to generate salt: %s", err)
		}

		enc, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), hashFunc)
		if err != nil {
			t.Fatalf("Test errored at encrypt (%s): %s", mdParam, err)
		}

		// WTF? Without "echo" openssl tells us "error reading input file"
		cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("echo \"%s\" | openssl aes-256-cbc -k %s -md %s -d -a", string(enc), passphrase, mdParam))

		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out

		err = cmd.Run()
		if err != nil {
			t.Errorf("OpenSSL errored (%s): %s", mdParam, err)
		}

		if out.String() != plaintext {
			t.Errorf("OpenSSL output did not match input.\nOutput was (%s): %s", mdParam, out.String())
		}
	}
}

func TestGenerateSalt(t *testing.T) {
	knownSalts := [][]byte{}

	o := New()

	for i := 0; i < 10; i++ {
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

	if _, err := o.EncryptStringWithSalt(passphrase, []byte("12345"), plaintext); err != ErrInvalidSalt {
		t.Errorf("5-character salt was accepted, needs to have 8 character")
	}

	if _, err := o.EncryptStringWithSalt(passphrase, []byte("1234567890"), plaintext); err != ErrInvalidSalt {
		t.Errorf("10-character salt was accepted, needs to have 8 character")
	}

	if _, err := o.EncryptStringWithSalt(passphrase, []byte{0xcb, 0xd5, 0x1a, 0x3, 0x84, 0xba, 0xa8, 0xc8}, plaintext); err == ErrInvalidSalt {
		t.Errorf("Salt with 8 byte unprintable characters was not accepted")
	}
}

func benchmarkDecrypt(ciphertext string, b *testing.B) {
	passphrase := "z4yH36a6zerhfE5427ZV"
	o := New()

	for n := 0; n < b.N; n++ {
		o.DecryptString(passphrase, ciphertext)
	}
}

func BenchmarkDecryptMD5(b *testing.B) {
	benchmarkDecrypt("U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU=", b)
}

func BenchmarkDecryptSHA1(b *testing.B) {
	benchmarkDecrypt("U2FsdGVkX1/Yy9kegseq2Ewd4UvjFYCpIEA1cltTA1Q=", b)
}

func BenchmarkDecryptSHA256(b *testing.B) {
	benchmarkDecrypt("U2FsdGVkX1+O68d7BO9ibP8nB5+xtb/27IHlyjJWpl8=", b)
}

func benchmarkEncrypt(plaintext string, hashFunc DigestFunc, b *testing.B) {
	passphrase := "z4yH36a6zerhfE5427ZV"
	o := New()
	salt, _ := o.GenerateSalt()

	for n := 0; n < b.N; n++ {
		o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), hashFunc)
	}
}

func BenchmarkEncryptMD5(b *testing.B) {
	benchmarkEncrypt("hallowelt", DigestMD5Sum, b)
}

func BenchmarkEncryptSHA1(b *testing.B) {
	benchmarkEncrypt("hallowelt", DigestSHA1Sum, b)
}

func BenchmarkEncryptSHA256(b *testing.B) {
	benchmarkEncrypt("hallowelt", DigestSHA256Sum, b)
}

func BenchmarkGenerateSalt(b *testing.B) {
	o := New()
	for n := 0; n < b.N; n++ {
		o.GenerateSalt()
	}
}
