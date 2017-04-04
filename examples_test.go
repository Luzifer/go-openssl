package openssl

import "fmt"

func ExampleOpenSSL_EncryptString() {
	plaintext := "Hello World!"
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	enc, err := o.EncryptString(passphrase, plaintext)
	if err != nil {
		fmt.Printf("An error occurred: %s\n", err)
	}

	fmt.Printf("Encrypted text: %s\n", string(enc))
}

func ExampleOpenSSL_DecryptString() {
	opensslEncrypted := "U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="
	passphrase := "z4yH36a6zerhfE5427ZV"

	o := New()

	dec, err := o.DecryptString(passphrase, opensslEncrypted)
	if err != nil {
		fmt.Printf("An error occurred: %s\n", err)
	}

	fmt.Printf("Decrypted text: %s\n", string(dec))

	// Output:
	// Decrypted text: hallowelt
}
