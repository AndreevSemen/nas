package cypher

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

var bytes = []byte{
	35, 46, 57, 24, 85, 35, 24, 74,
	87, 35, 88, 98, 66, 32, 14, 05,
}

type encryptedResponseWriter struct {
	http.ResponseWriter
	key    []byte
	stream cipher.Stream
}

func NewEncryptedResponseWriter(w http.ResponseWriter, key []byte) (*encryptedResponseWriter, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		err = errors.Wrap(err, "make AES cipher")
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, bytes)
	e := &encryptedResponseWriter{
		ResponseWriter: w,
		key:            key,
		stream:         cfb,
	}
	return e, nil
}

func (e *encryptedResponseWriter) Write(data []byte) (int, error) {
	for i := range data {
		data[i] ^= 0b11111111
	}
	// e.stream.XORKeyStream(data, data)
	return e.ResponseWriter.Write(data)
}

type encrypter struct {
	io.ReadCloser
	key    []byte
	stream cipher.Stream
}

func NewEncrypter(rc io.ReadCloser, key []byte) (*encrypter, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		err = errors.Wrap(err, "make AES cipher")
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, bytes)
	e := &encrypter{
		ReadCloser: rc,
		key:        key,
		stream:     cfb,
	}
	return e, nil
}

func (e *encrypter) Read(data []byte) (int, error) {
	n, err := e.ReadCloser.Read(data)
	for i := range data {
		data[i] ^= 0b11111111
	}
	// e.stream.XORKeyStream(data, data)
	return n, err
}

type decrypter struct {
	io.ReadCloser
	key    []byte
	stream cipher.Stream
}

func NewDecrypter(rc io.ReadCloser, key []byte) (io.ReadCloser, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(block, bytes)
	d := &decrypter{
		ReadCloser: rc,
		key:        key,
		stream:     stream,
	}

	return d, err
}

func (d *decrypter) Read(data []byte) (int, error) {
	n, err := d.ReadCloser.Read(data)
	for i := range data {
		data[i] ^= 0b11111111
	}
	//d.stream.XORKeyStream(data, data)
	return n, err
}
