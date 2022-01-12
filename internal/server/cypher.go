package server

import (
	"net/http"

	"github.com/AndreevSemen/nas/internal/cypher"
	"github.com/AndreevSemen/nas/internal/utilities"
	"github.com/monnand/dhkx"
	"github.com/sirupsen/logrus"
)

func (fs *FileServer) generateSharedKey(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithField("logging-entity", "auth/generate_shared_key")
	// Get a group. Use the default one would be enough.
	g, _ := dhkx.GetGroup(0)

	// Generate a private key from the group.
	// Use the default random number generator.
	priv, err := g.GeneratePrivateKey(nil)
	if err != nil {
		logger.Error(err.Error())
		responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Get the public key from the private key.
	pub := priv.Bytes()

	// Receive a slice of bytes from Alice, which contains Alice's public key
	alicePubKeyBase64 := r.Header.Get("Public-Key")
	if alicePubKeyBase64 == "" {
		responseWithError(logger, w, ErrNoPublicKey, http.StatusBadRequest)
		return
	}

	alicePubKeyBytes, err := utilities.DecodeBase64(alicePubKeyBase64)
	if err != nil {
		logger.Error(err.Error())
		responseWithError(logger, w, ErrBadPublicKeyFormat, http.StatusBadRequest)
		return
	}

	// Recover Alice's public key
	alicePubKey := dhkx.NewPublicKey(alicePubKeyBytes)

	// Compute the key
	k, err := g.ComputeKey(alicePubKey, priv)
	if err != nil {
		logger.Error(err.Error())
		responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
		return
	}

	sharedKey := k.Bytes()
	if err := fs.db.SetSharedKey(alicePubKeyBytes, sharedKey); err != nil {
		logger.Error(err.Error())
		responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Send the public key to Alice.
	pubKeyBase64, err := utilities.EncodeBase64(pub)
	if err != nil {
		logger.Error(err.Error())
		responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Public-Key", pubKeyBase64)
}

func (fs *FileServer) middlewareCypher(next http.Handler) http.Handler {
	logger := logrus.WithField("logging-entity", "auth/cipher")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alicePubKeyBase64 := r.Header.Get("Public-Key")
		if alicePubKeyBase64 == "" {
			responseWithError(logger, w, ErrNoPublicKey, http.StatusBadRequest)
			return
		}
		key, err := utilities.DecodeBase64(alicePubKeyBase64)
		if err != nil {
			logger.Error(err.Error())
			responseWithError(logger, w, ErrBadPublicKeyFormat, http.StatusBadRequest)
			return
		}

		r.Body, err = cypher.NewDecrypter(r.Body, key)
		if err != nil {
			logger.Error(err.Error())
			responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
			return
		}

		w, err = cypher.NewEncryptedResponseWriter(w, key)
		if err != nil {
			logger.Error(err.Error())
			responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})
}
