package openssl

import "fmt"

// #nosec G101 -- Contains harcoded test passphrase
func ExampleOpenSSL_EncryptBytes() {
	plaintext := "Hello World!"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	enc, err := o.EncryptBytes(passphrase, []byte(plaintext), PBKDF2SHA256)
	if err != nil {
		fmt.Printf("An error occurred: %s\n", err)
	}

	fmt.Printf("Encrypted text: %s\n", string(enc))
}

// #nosec G101 -- Contains harcoded test passphrase
func ExampleOpenSSL_DecryptBytes() {
	opensslEncrypted := "U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	dec, err := o.DecryptBytes(passphrase, []byte(opensslEncrypted), BytesToKeyMD5)
	if err != nil {
		fmt.Printf("An error occurred: %s\n", err)
	}

	fmt.Printf("Decrypted text: %s\n", string(dec))

	// Output:
	// Decrypted text: hallowelt
}
