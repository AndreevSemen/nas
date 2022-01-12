package cypher

// import (
// 	"io"
// 	"net/http"
// )

// type encryptedResponseWriter struct {
// 	http.ResponseWriter
// 	key []byte
// }

// func NewEncryptedResponseWriter(w http.ResponseWriter, key []byte) *encryptedResponseWriter {
// 	return &encryptedResponseWriter{
// 		ResponseWriter: w,
// 		key:            key,
// 	}
// }

// func (e *encryptedResponseWriter) Write(data []byte) (int, error) {

// }

// type decrypter struct {
// 	io.ReadCloser
// 	key []byte
// }

// func NewDecrypter(rc io.ReadCloser, key []byte) io.ReadCloser {
// 	return &decrypter{
// 		ReadCloser: rc,
// 		key:        key,
// 	}
// }

// func (d *decrypter) Read(p []byte) (n int, err error) {

// }
