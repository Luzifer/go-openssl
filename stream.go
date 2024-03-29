package openssl

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// DecryptReader represents an io.Reader for OpenSSL encrypted data
type DecryptReader struct {
	r          *bufio.Reader
	mode       cipher.BlockMode
	cg         CredsGenerator
	passphrase []byte

	buf bytes.Buffer
}

// NewReader creates a new OpenSSL stream reader with underlying reader,
// passphrase and CredsGenerator
func NewReader(r io.Reader, passphrase string, cg CredsGenerator) *DecryptReader {
	return &DecryptReader{
		r:          bufio.NewReader(r),
		cg:         cg,
		passphrase: []byte(passphrase),
	}
}

// Read implements the io.Reader interface to read from an encrypted
// datastream
func (d *DecryptReader) Read(b []byte) (int, error) {
	if d.mode == nil {
		if err := d.initMode(); err != nil {
			return 0, fmt.Errorf("initializing mode: %w", err)
		}
	}

	n, err := d.r.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("reading from underlying reader: %w", err)
	}

	// write original data to buffer first
	if _, err := d.buf.Write(b[:n]); err != nil {
		return 0, fmt.Errorf("writing bytes to buffer: %w", err)
	}

	realSize := len(b)
	if d.buf.Len() < realSize {
		realSize = d.buf.Len()
	}

	size := (realSize / aes.BlockSize) * aes.BlockSize

	if size == 0 {
		return 0, nil
	}

	// read encrypted data from buffer
	if _, err := io.ReadFull(&d.buf, b[:size]); err != nil {
		return size, fmt.Errorf("reading from underlying reader: %w", err)
	}

	d.mode.CryptBlocks(b[:size], b[:size])

	// AS OpenSSL enforces the encrypted data to have a length of a
	// multiple of the AES BlockSize we will always read full blocks.
	// Therefore we can check whether the next block exists or yields
	// an io.EOF error. If it does we need to remove the PKCS7 padding.
	if _, err := d.r.Peek(aes.BlockSize); errors.Is(err, io.EOF) {
		if _, err := io.Copy(&d.buf, d.r); err != nil {
			return size, fmt.Errorf("copying remaining data to buffer: %w", err)
		}

		if d.buf.Len() == 0 {
			size -= int(b[size-1])
			if size < 0 {
				return 0, fmt.Errorf("incorrect padding size: %d", size)
			}
			return size, io.EOF
		}

		if d.buf.Len()%aes.BlockSize != 0 {
			return size, fmt.Errorf("incorrect encrypted data size: %d", d.buf.Len())
		}
	}

	return size, nil
}

func (d *DecryptReader) initMode() error {
	if d.mode != nil {
		return nil
	}

	saltHeader := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(d.r, saltHeader); err != nil {
		return fmt.Errorf("reading salt header: %w", err)
	}

	if string(saltHeader[:8]) != opensslSaltHeader {
		return fmt.Errorf("missing OpenSSL salt-header")
	}

	salt := saltHeader[8:]

	creds, err := d.cg(d.passphrase, salt)
	if err != nil {
		return err
	}

	c, err := aes.NewCipher(creds.Key)
	if err != nil {
		return fmt.Errorf("creating new AES cipher: %w", err)
	}
	d.mode = cipher.NewCBCDecrypter(c, creds.IV)
	return nil
}

// EncryptWriter represents an io.WriteCloser info OpenSSL encrypted data
type EncryptWriter struct {
	mode       cipher.BlockMode
	w          io.Writer
	cg         CredsGenerator
	passphrase []byte
	buf        []byte
}

// NewWriter create new openssl stream writer with underlying writer,
// passphrase and CredsGenerator.
//
// Make sure close the writer after writing all data, to ensure the
// remaining data is padded and written to the underlying writer.
func NewWriter(w io.Writer, passphrase string, cg CredsGenerator) *EncryptWriter {
	return &EncryptWriter{
		w:          w,
		cg:         cg,
		passphrase: []byte(passphrase),
	}
}

// Write implements io.WriteCloser to write encrypted data into the
// underlying writer. The Write call may keep data in the buffer and
// needs to flush them through the Close function.
func (e *EncryptWriter) Write(b []byte) (int, error) {
	if e.mode == nil {
		if err := e.initMode(); err != nil {
			return 0, err
		}
	}

	originSize := len(b)

	buf := bytes.NewBuffer(nil)

	if e.buf != nil {
		if _, err := buf.Write(e.buf); err != nil {
			return 0, fmt.Errorf("writing remaining data to buffer: %w", err)
		}
		e.buf = nil
	}

	if _, err := buf.Write(b); err != nil {
		return 0, fmt.Errorf("writing current data to buffer: %w", err)
	}

	size := (buf.Len() / aes.BlockSize) * aes.BlockSize

	if remain := buf.Len() - size; remain > 0 {
		e.buf = buf.Bytes()[size:]
	}

	if size == 0 {
		return originSize, nil
	}

	e.mode.CryptBlocks(buf.Bytes()[:size], buf.Bytes()[:size])

	n, err := e.w.Write(buf.Bytes()[:size])
	if err != nil {
		return n, fmt.Errorf("writing encrypted data to underlying writer: %w", err)
	}

	return originSize, nil
}

// Close writes any buffered data to the underlying io.Writer.
// Make sure close the writer after write all data.
func (e *EncryptWriter) Close() error {
	padlen := 1
	for ((len(e.buf) + padlen) % aes.BlockSize) != 0 {
		padlen++
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	pad = append(e.buf, pad...)

	e.buf = nil
	e.mode.CryptBlocks(pad, pad)

	if _, err := e.w.Write(pad); err != nil {
		return fmt.Errorf("writing padding to underlying writer: %w", err)
	}

	return nil
}

func (e *EncryptWriter) initMode() error {
	if e.mode != nil {
		return nil
	}

	salt := make([]byte, opensslSaltLength) // Generate an 8 byte salt
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return fmt.Errorf("reading salt: %w", err)
	}

	_, err = e.w.Write(append([]byte(opensslSaltHeader), salt...))
	if err != nil {
		return fmt.Errorf("writing salt to underlying writer: %w", err)
	}

	creds, err := e.cg(e.passphrase, salt)
	if err != nil {
		return err
	}

	c, err := aes.NewCipher(creds.Key)
	if err != nil {
		return fmt.Errorf("creating new AES cipher: %w", err)
	}
	e.mode = cipher.NewCBCEncrypter(c, creds.IV)
	return nil
}
