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

type decryptReader struct {
	r          *bufio.Reader
	mode       cipher.BlockMode
	cg         CredsGenerator
	passphrase []byte
}

// NewReader create new openssl stream reader with underlying reader,
// passphrase and credsGenerator
func NewReader(r io.Reader, passphrase string, cg CredsGenerator) io.Reader {
	return &decryptReader{
		r:          bufio.NewReader(r),
		cg:         cg,
		passphrase: []byte(passphrase),
	}
}

func (d *decryptReader) initMode() error {
	if d.mode != nil {
		return nil
	}

	saltHeader := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(d.r, saltHeader); err != nil {
		return fmt.Errorf("read salt header failed: %w", err)
	}

	if string(saltHeader[:8]) != "Salted__" {
		return fmt.Errorf("does not appear to have been encrypted with OpenSSL, salt header missing")
	}

	salt := saltHeader[8:]

	creds, err := d.cg(d.passphrase, salt)
	if err != nil {
		return err
	}

	c, err := aes.NewCipher(creds.Key)
	if err != nil {
		return fmt.Errorf("new aes cipher failed: %w", err)
	}
	d.mode = cipher.NewCBCDecrypter(c, creds.IV)
	return nil
}

func (d *decryptReader) Read(b []byte) (int, error) {
	if d.mode == nil {
		if err := d.initMode(); err != nil {
			return 0, fmt.Errorf("init failed: %w", err)
		}
	}

	size := (len(b) / aes.BlockSize) * aes.BlockSize

	if size == 0 {
		return 0, nil
	}

	n, err := d.r.Read(b[:size])
	if err != nil {
		return n, err
	}

	d.mode.CryptBlocks(b[:n], b[:n])

	// check is last block of data, then remove padding.
	if _, err = d.r.Peek(aes.BlockSize); errors.Is(err, io.EOF) {
		n -= int(b[n-1])
	}

	return n, nil
}

type encryptWriter struct {
	mode       cipher.BlockMode
	w          io.Writer
	cg         CredsGenerator
	passphrase []byte
	buf        []byte
}

// NewWriter create new openssl stream writer with underlying writer,
// passphrase and credsGenerator.
// Make sure close the writer after write all data, that will flush all
// remaining data and padding to underlying.
func NewWriter(w io.Writer, passphrase string, cg CredsGenerator) io.WriteCloser {
	return &encryptWriter{
		w:          w,
		cg:         cg,
		passphrase: []byte(passphrase),
	}
}

func (e *encryptWriter) initMode() error {
	if e.mode != nil {
		return nil
	}

	salt := make([]byte, 8) // Generate an 8 byte salt
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return fmt.Errorf("read salt failed: %w", err)
	}

	_, err = e.w.Write(append([]byte("Salted__"), salt...))
	if err != nil {
		return fmt.Errorf("write salt to underlying writer failed: %w", err)
	}

	creds, err := e.cg(e.passphrase, salt)
	if err != nil {
		return err
	}

	c, err := aes.NewCipher(creds.Key)
	if err != nil {
		return fmt.Errorf("new aes cipher failed: %w", err)
	}
	e.mode = cipher.NewCBCEncrypter(c, creds.IV)
	return nil
}

func (e *encryptWriter) Write(b []byte) (int, error) {
	if e.mode == nil {
		if err := e.initMode(); err != nil {
			return 0, err
		}
	}

	originSize := len(b)

	buf := bytes.NewBuffer(nil)

	if e.buf != nil {
		if _, err := buf.Write(e.buf); err != nil {
			return 0, fmt.Errorf("write last remain data to buf failed: %w", err)
		}
		e.buf = nil
	}

	if _, err := buf.Write(b); err != nil {
		return 0, fmt.Errorf("write current data to buf failed: %w", err)
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
		return n, fmt.Errorf("write encrypted data to underlying writer failed: %w", err)
	}

	return originSize, nil
}

// Close writes any buffered data to the underlying io.Writer.
// make sure close the writer after write all data.
func (e *encryptWriter) Close() error {
	padlen := 1
	for ((len(e.buf) + padlen) % aes.BlockSize) != 0 {
		padlen++
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)

	pad = append(e.buf, pad...)
	e.buf = nil
	e.mode.CryptBlocks(pad, pad)
	_, err := e.w.Write(pad)
	if err != nil {
		return fmt.Errorf("write padding to underlying writer failed: %w", err)
	}

	return err
}
