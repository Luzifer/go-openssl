package openssl

import (
	"bytes"
	"crypto/aes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type onlyOneByteReader struct {
	size int
	r    io.Reader
}

func (o *onlyOneByteReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	return o.r.Read(b[:o.size])
}

func TestReader(t *testing.T) {
	o := New()

	pass := "abcd"
	plaintext := []byte("123abc,./vvvczcekdewfeojdosndsdlsndlncnepcnodcnviorf409eofnvkdfvjfvdsoijvo")

	data, err := o.EncryptBinaryBytes(pass, plaintext, BytesToKeyMD5)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	bytesBuf := make([]byte, aes.BlockSize+1)

	for i := 1; i <= aes.BlockSize+1; i++ {
		buf.Reset()
		r := &onlyOneByteReader{i, bytes.NewReader(data)}
		_, err = io.CopyBuffer(buf, NewReader(r, pass, BytesToKeyMD5), bytesBuf)
		require.NoError(t, err)
		require.Equal(t, plaintext, buf.Bytes())
	}
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
