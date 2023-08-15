package openssl

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReader(t *testing.T) {
	o := New()

	pass := "abcd"
	plaintext := []byte("123abc,./vvvczcekdewfeojdosndsdlsndlncnepcnodcnviorf409eofnvkdfvjfvdsoijvo")

	data, err := o.EncryptBinaryBytes(pass, plaintext, BytesToKeyMD5)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, NewReader(bytes.NewReader(data), pass, BytesToKeyMD5))
	require.NoError(t, err)
	require.Equal(t, buf.Bytes(), plaintext)
}

func TestWriter(t *testing.T) {
	o := New()

	pass := "abcd"
	plaintext := []byte("123abc,./vvvczcekdewfeojzaasdsddsdosnd432pdneonkefnoescndisbcisfheosfbdk vsdovsdn]sdlsndlncnepcnodcnviorf409eofnvkdfvjfvdsoijvo")

	buf := bytes.NewBuffer(nil)
	es := NewWriter(buf, pass, BytesToKeyMD5)

	_, err := es.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, es.Close())

	da, err := o.DecryptBinaryBytes(pass, buf.Bytes(), BytesToKeyMD5)
	require.NoError(t, err)

	require.Equal(t, da, plaintext)
}
