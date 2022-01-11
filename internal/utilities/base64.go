package utilities

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"strings"
)

func DecodeBase64(data string) ([]byte, error) {
	base64Decoder := base64.NewDecoder(
		base64.StdEncoding,
		strings.NewReader(data),
	)
	decoded, err := ioutil.ReadAll(base64Decoder)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func EncodeBase64(data []byte) (string, error) {
	base64Buf := bytes.NewBuffer(nil)
	base64Encoder := base64.NewEncoder(
		base64.StdEncoding,
		base64Buf,
	)
	_, err := base64Encoder.Write(data)
	if err != nil {
		return "", err
	}

	return base64Buf.String(), nil
}
