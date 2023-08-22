package openssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPassphrase = "z4yH36a6zerhfE5427ZV" //#nosec G101 -- Is hardcoded passphrase but only for testing purposes
	testPlaintext  = "hallowelt"
)

var testTable = []struct {
	tName    string
	tMdParam string
	tMdFunc  CredsGenerator
	tPBKDF   bool
}{
	{"MD5", "md5", BytesToKeyMD5, false},
	{"SHA1", "sha1", BytesToKeySHA1, false},
	{"SHA256", "sha256", BytesToKeySHA256, false},
	{"SHA384", "sha384", BytesToKeySHA384, false},
	{"SHA512", "sha512", BytesToKeySHA512, false},
	{"PBKDF2_MD5", "md5", PBKDF2MD5, true},
	{"PBKDF2_SHA1", "sha1", PBKDF2SHA1, true},
	{"PBKDF2_SHA256", "sha256", PBKDF2SHA256, true},
	{"PBKDF2_SHA384", "sha384", PBKDF2SHA384, true},
	{"PBKDF2_SHA512", "sha512", PBKDF2SHA512, true},
}

func TestBinaryEncryptToDecryptWithCustomSalt(t *testing.T) {
	salt := []byte("saltsalt")

	o := New()

	enc, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBinaryBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestBinaryEncryptToDecrypt(t *testing.T) {
	o := New()

	enc, err := o.EncryptBinaryBytes(testPassphrase, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBinaryBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestBinaryEncryptToOpenSSL(t *testing.T) {
	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			salt, err := o.GenerateSalt()
			require.NoError(t, err)

			enc, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), tc.tMdFunc)
			require.NoError(t, err)

			// Need to specify /dev/stdin as file so that we can pass in binary
			// data to openssl without creating a file
			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-d",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine

			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stdin = bytes.NewBuffer(enc)

			err = cmd.Run()
			require.NoError(t, err)

			assert.Equal(t, testPlaintext, out.String())
		})
	}
}

func TestBinaryEncryptWithSaltShouldHaveSameOutput(t *testing.T) {
	plaintext := "outputshouldbesame"
	passphrase := "passphrasesupersecure"
	salt := []byte("saltsalt")

	o := New()

	enc1, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	enc2, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2)
}

func TestDecryptBinaryFromString(t *testing.T) {
	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			var out bytes.Buffer

			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine
			cmd.Stdout = &out
			cmd.Stdin = strings.NewReader(testPlaintext)

			require.NoError(t, cmd.Run())

			data, err := o.DecryptBinaryBytes(testPassphrase, out.Bytes(), tc.tMdFunc)
			require.NoError(t, err)

			if !assert.Equal(t, testPlaintext, string(data)) {
				t.Logf("Data: %s\nPlaintext: %s", string(data), testPlaintext)
			}
		})
	}
}

func TestDecryptFromString(t *testing.T) {
	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			var out bytes.Buffer

			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-base64",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine
			cmd.Stdout = &out
			cmd.Stdin = strings.NewReader(testPlaintext)

			require.NoError(t, cmd.Run())

			data, err := o.DecryptBytes(testPassphrase, out.Bytes(), tc.tMdFunc)
			require.NoError(t, err)

			if !assert.Equal(t, testPlaintext, string(data)) {
				t.Logf("Data: %s\nPlaintext: %s", string(data), testPlaintext)
			}
		})
	}
}

func TestEncryptToDecrypt(t *testing.T) {
	o := New()

	enc, err := o.EncryptBytes(testPassphrase, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestEncryptToDecryptWithCustomSalt(t *testing.T) {
	salt := []byte("saltsalt")

	o := New()

	enc, err := o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestEncryptToOpenSSL(t *testing.T) {
	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			o := New()

			salt, err := o.GenerateSalt()
			require.NoError(t, err)

			enc, err := o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), tc.tMdFunc)
			require.NoError(t, err)

			enc = append(enc, '\n')

			var out bytes.Buffer

			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-base64", "-d",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine
			cmd.Stdout = &out
			cmd.Stdin = bytes.NewReader(enc)

			require.NoError(t, cmd.Run())

			assert.Equal(t, testPlaintext, out.String())
		})
	}
}

func TestEncryptWithSaltShouldHaveSameOutput(t *testing.T) {
	plaintext := "outputshouldbesame"
	passphrase := "passphrasesupersecure"
	salt := []byte("saltsalt")

	o := New()

	enc1, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	enc2, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2)
}

func TestGenerateSalt(t *testing.T) {
	knownSalts := [][]byte{}

	o := New()

	for i := 0; i < 1000; i++ {
		salt, err := o.GenerateSalt()
		require.NoError(t, err)

		for _, ks := range knownSalts {
			assert.NotEqual(t, ks, salt)
			knownSalts = append(knownSalts, salt)
		}
	}
}

func TestSaltValidation(t *testing.T) {
	var err error
	o := New()

	_, err = o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, []byte("12345"), []byte(testPlaintext), BytesToKeySHA256)
	assert.ErrorIs(t, err, ErrInvalidSalt)

	_, err = o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, []byte("1234567890"), []byte(testPlaintext), BytesToKeySHA256)
	assert.ErrorIs(t, err, ErrInvalidSalt)

	_, err = o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, []byte{0xcb, 0xd5, 0x1a, 0x3, 0x84, 0xba, 0xa8, 0xc8}, []byte(testPlaintext), BytesToKeySHA256)
	assert.NoError(t, err)
}

//
// Benchmarks
//

func benchmarkDecrypt(ciphertext []byte, cg CredsGenerator, b *testing.B) {
	o := New()

	for n := 0; n < b.N; n++ {
		_, err := o.DecryptBytes(testPassphrase, ciphertext, cg)
		require.NoError(b, err)
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
	o := New()
	salt, _ := o.GenerateSalt()

	for n := 0; n < b.N; n++ {
		_, err := o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(plaintext), cg)
		require.NoError(b, err)
	}
}

func BenchmarkEncryptMD5(b *testing.B) {
	benchmarkEncrypt(testPlaintext, BytesToKeyMD5, b)
}

func BenchmarkEncryptSHA1(b *testing.B) {
	benchmarkEncrypt(testPlaintext, BytesToKeySHA1, b)
}

func BenchmarkEncryptSHA256(b *testing.B) {
	benchmarkEncrypt(testPlaintext, BytesToKeySHA256, b)
}

func BenchmarkGenerateSalt(b *testing.B) {
	o := New()
	for n := 0; n < b.N; n++ {
		_, err := o.GenerateSalt()
		require.NoError(b, err)
	}
}
