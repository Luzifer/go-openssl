package openssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"
)

func TestDecryptFromString(t *testing.T) {
	// > echo -n "hallowelt" | openssl aes-256-cbc -pass pass:z4yH36a6zerhfE5427ZV -a -salt
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

	o := New()

	enc, err := o.EncryptString(passphrase, plaintext)
	if err != nil {
		t.Fatalf("Test errored at encrypt: %s", err)
	}

	// WTF? Without "echo" openssl tells us "error reading input file"
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("echo \"%s\" | openssl aes-256-cbc -k %s -d -a", string(enc), passphrase))

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if err != nil {
		t.Errorf("OpenSSL errored: %s", err)
	}

	if out.String() != plaintext {
		t.Errorf("OpenSSL output did not match input.\nOutput was: %s", out.String())
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
