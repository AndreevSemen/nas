package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/AndreevSemen/nas/internal/config"
	"github.com/AndreevSemen/nas/internal/cypher"
	"github.com/AndreevSemen/nas/internal/structures"
	"github.com/AndreevSemen/nas/internal/utilities"
	"github.com/monnand/dhkx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type NasClient struct {
	cfg       config.ClientConfig
	client    *http.Client
	pubBase64 string
	sharedKey []byte
	token     string
}

func NewClient(cfg config.ClientConfig, login, password string) (*NasClient, error) {
	logger := logrus.WithField("logging-entity", "dialer")

	// Get a group. Use the default one would be enough.
	g, _ := dhkx.GetGroup(0)

	// Generate a private key from the group.
	// Use the default random number generator.
	priv, _ := g.GeneratePrivateKey(nil)

	// Get the public key from the private key.
	pub := priv.Bytes()

	pubBase64, err := utilities.EncodeBase64(pub)
	if err != nil {
		err = errors.Wrap(err, "encode public key in base64")
		return nil, err
	}

	client := &http.Client{}

	// Create a pool with the server certificate since it is not signed
	// by a known CA
	caCert, err := ioutil.ReadFile(cfg.CertPath)
	if err != nil {
		err = errors.Wrap(err, "read server certificate")
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Use the proper transport in the client
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	logger.Infof("key generating with host %s", cfg.ServerAddr)

	// Send the public key to Bob.
	req, err := newRequest(http.MethodGet, cfg.ServerAddr, "/generate_shared_key", nil, nil)
	if err != nil {
		err = errors.Wrap(err, "make request")
		return nil, err
	}
	req.Header.Set("Public-Key", pubBase64)

	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrap(err, "do generate shared key")
		return nil, err
	}
	resp.Body.Close()

	// Receive a slice of bytes from Bob, which contains Bob's public key
	bobPubKeyBase64 := resp.Header.Get("Public-Key")
	if bobPubKeyBase64 == "" {
		err = errors.Wrap(err, "got empty public key")
		return nil, err
	}

	bobPubKeyBytes, err := utilities.DecodeBase64(bobPubKeyBase64)
	if err != nil {
		return nil, err
	}
	// Recover Bob's public key
	bobPubKey := dhkx.NewPublicKey(bobPubKeyBytes)

	// Compute the key
	k, _ := g.ComputeKey(bobPubKey, priv)

	// Get the key in the form of []byte
	sharedKey := k.Bytes()

	nc := &NasClient{
		cfg:       cfg,
		client:    client,
		pubBase64: pubBase64,
		sharedKey: sharedKey,
	}

	creds := structures.Credentials{
		Login:    login,
		Password: password,
	}

	body, err := json.Marshal(creds)
	if err != nil {
		err = errors.Wrap(err, "marshal credentials")
		return nil, err
	}

	req, err = newRequest(http.MethodGet, cfg.ServerAddr, "/sign_in", ioutil.NopCloser(bytes.NewBuffer(body)), sharedKey)
	if err != nil {
		err = errors.Wrap(err, "make request")
		return nil, err
	}
	req.Header.Set("Public-Key", pubBase64)

	resp, err = nc.doRequest(req)
	if err != nil {
		err = errors.Wrap(err, "do sign in")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			err = errors.Wrap(err, "read response body")
			return nil, err
		}

		return nil, errors.New(string(body))
	}

	token := resp.Header.Get("Authorization")
	if token == "" {
		err = errors.New("got no token from server")
		return nil, err
	}
	nc.token = token

	return nc, nil
}

func (nc *NasClient) DownloadStorage(sourcePath, destinationPath string) error {
	list, err := nc.list(sourcePath)
	if err != nil {
		return err
	}

	if err := os.Mkdir(filepath.Join(destinationPath, sourcePath), 0777); err != nil {
		err = errors.Wrap(err, "mkdir")
		return err
	}

	for _, item := range list {
		if item.IsDir {
			if err := nc.DownloadStorage(
				item.Path,
				destinationPath,
			); err != nil {
				err = errors.Wrap(err, "download subdir")
				return err
			}
		} else {
			req, err := newRequest(http.MethodGet, nc.cfg.ServerAddr, item.Path, nil, nc.sharedKey)
			if err != nil {
				err = errors.Wrap(err, "make request")
				return err
			}
			req.Header.Set("Public-Key", nc.pubBase64)
			req.Header.Set("Authorization", nc.token)

			resp, err := nc.doRequest(req)
			if err != nil {
				err = errors.Wrap(err, "download file")
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					err = errors.Wrap(err, "read response body")
					return err
				}

				err = errors.New(string(body))
				err = errors.Wrap(err, "download file")
				return err
			}

			f, err := os.Create(filepath.Join(destinationPath, item.Path))
			if err != nil {
				err = errors.Wrap(err, "create file")
				return err
			}

			if _, err := io.Copy(f, resp.Body); err != nil {
				f.Close()
				err = errors.Wrap(err, "read content to file")
				return err
			}
			f.Close()

			logrus.WithField("logging-entity", "downloader").Infof("file '%s' downloaded", item.Path)
		}
	}

	return nil
}

func (nc *NasClient) SyncStorage(sourcePath, destinationPath string) error {
	list, err := nc.list(destinationPath)
	if err != nil {
		return err
	}

	for _, item := range list {
		req, err := newRequest(http.MethodDelete, nc.cfg.ServerAddr, item.Path, nil, nc.sharedKey)
		if err != nil {
			err = errors.Wrap(err, "make request")
			return err
		}
		req.Header.Set("Public-Key", nc.pubBase64)
		req.Header.Set("Authorization", nc.token)

		resp, err := nc.doRequest(req)
		if err != nil {
			err = errors.Wrap(err, "delete files before sync")
			return err
		}
		defer resp.Body.Close()
	}

	var items []structures.ListItem
	if err := filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if path != sourcePath {
			items = append(items, structures.ListItem{
				Path:  strings.TrimPrefix(path, sourcePath),
				IsDir: info.IsDir(),
			})
		}

		return nil
	}); err != nil {
		err = errors.Wrap(err, "walk source files")
		return err
	}

	for _, item := range items {
		var req *http.Request
		if item.IsDir {
			req, err = newRequest(http.MethodPut, nc.cfg.ServerAddr, filepath.Join(destinationPath, item.Path), nil, nc.sharedKey)
			if err != nil {
				err = errors.Wrap(err, "make request")
				return err
			}
			q := req.URL.Query()
			q.Set("is_dir", "true")
			req.URL.RawQuery = q.Encode()
		} else {
			f, err := os.Open(filepath.Join(sourcePath, item.Path))
			if err != nil {
				err = errors.Wrap(err, "open file before sync")
				return err
			}
			req, err = newRequest(http.MethodPut, nc.cfg.ServerAddr, filepath.Join(destinationPath, item.Path), f, nc.sharedKey)
			if err != nil {
				err = errors.Wrap(err, "make request")
				return err
			}
		}
		req.Header.Set("Public-Key", nc.pubBase64)
		req.Header.Set("Authorization", nc.token)

		resp, err := nc.doRequest(req)
		if err != nil {
			err = errors.Wrap(err, "sync file")
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				err = errors.Wrap(err, "read response body")
				return err
			}

			err = errors.New(string(body))
			err = errors.Wrap(err, "sync file")
			return err
		}

		logrus.WithField("logging-entity", "synchronizer").Infof("file '%s' synced", item.Path)
	}

	return nil
}

func (nc *NasClient) list(sourcePath string) ([]structures.ListItem, error) {
	req, err := newRequest(http.MethodGet, nc.cfg.ServerAddr, sourcePath, nil, nc.sharedKey)
	if err != nil {
		err = errors.Wrap(err, "make request")
		return nil, err
	}
	req.Header.Set("Public-Key", nc.pubBase64)
	req.Header.Set("Authorization", nc.token)

	q := req.URL.Query()
	q.Set("list", "true")
	req.URL.RawQuery = q.Encode()

	resp, err := nc.doRequest(req)
	if err != nil {
		err = errors.Wrap(err, "do list storage files")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			err = errors.Wrap(err, "read response body")
			return nil, err
		}

		err = errors.New(string(body))
		err = errors.Wrap(err, "do list storage files")
		return nil, err
	}

	var list []structures.ListItem
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		err = errors.Wrap(err, "decode list")
		return nil, err
	}

	return list, nil
}

func (nc *NasClient) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := nc.client.Do(req)
	if err != nil {
		return nil, err
	}

	decBody, err := cypher.NewDecrypter(resp.Body, nc.sharedKey)
	if err != nil {
		return nil, err
	}
	resp.Body = decBody

	return resp, nil
}

func newRequest(method, serverAddr, path string, body io.ReadCloser, key []byte) (*http.Request, error) {
	if key != nil && body != nil {
		encBody, err := cypher.NewEncrypter(body, key)
		if err != nil {
			return nil, err
		}
		body = encBody
	}
	req := &http.Request{
		Method: method,
		URL: &url.URL{
			Scheme: "https",
			Host:   serverAddr,
			Path:   path,
		},
		Body:   body,
		Header: http.Header{},
	}
	return req, nil
}
