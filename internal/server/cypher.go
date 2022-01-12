package server

import (
	"net/http"

	"github.com/AndreevSemen/nas/internal/utilities"
	"github.com/monnand/dhkx"
	"github.com/sirupsen/logrus"
)

func (fs *FileServer) generateSharedKey(w http.ResponseWriter, r *http.Request) {
	// Get a group. Use the default one would be enough.
	g, _ := dhkx.GetGroup(0)

	// Generate a private key from the group.
	// Use the default random number generator.
	priv, err := g.GeneratePrivateKey(nil)
	if err != nil {
		logrus.WithField("logging-entity", "auth/generate_shared_key").Error(err.Error())
		responseWithError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Get the public key from the private key.
	pub := priv.Bytes()

	// Receive a slice of bytes from Alice, which contains Alice's public key
	alicePubKeyBase64 := r.Header.Get("Public-Key")
	if alicePubKeyBase64 == "" {
		responseWithError(w, ErrNoPublicKey, http.StatusBadRequest)
		return
	}

	alicePubKeyBytes, err := utilities.DecodeBase64(alicePubKeyBase64)
	if err != nil {
		logrus.WithField("logging-entity", "auth/generate_shared_key").Error(err.Error())
		responseWithError(w, ErrBadPublicKeyFormat, http.StatusBadRequest)
		return
	}

	// Recover Alice's public key
	alicePubKey := dhkx.NewPublicKey(alicePubKeyBytes)

	// Compute the key
	k, err := g.ComputeKey(alicePubKey, priv)
	if err != nil {
		logrus.WithField("logging-entity", "auth/generate_shared_key").Error(err.Error())
		responseWithError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	sharedKey := k.Bytes()
	if err := fs.db.SetSharedKey(alicePubKeyBytes, sharedKey); err != nil {
		logrus.WithField("logging-entity", "auth/generate_shared_key").Error(err.Error())
		responseWithError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Send the public key to Alice.
	pubKeyBase64, err := utilities.EncodeBase64(pub)
	if err != nil {
		logrus.WithField("logging-entity", "auth/generate_shared_key").Error(err.Error())
		responseWithError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Public-Key", pubKeyBase64)
}

func (fs *FileServer) middlewareCypher(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// alicePubKeyBase64 := r.Header.Get("Public-Key")
		// if alicePubKeyBase64 == "" {
		// 	responseWithError(w, ErrNoPublicKey, http.StatusBadRequest)
		// 	return
		// }
		// key, err := utilities.DecodeBase64(alicePubKeyBase64)
		// if err != nil {
		// 	logrus.WithField("logging-entity", "auth/generate_shared_key").Error(err.Error())
		// 	responseWithError(w, ErrBadPublicKeyFormat, http.StatusBadRequest)
		// 	return
		// }

		// r.Body = cypher.NewDecrypter(r.Body, key)
		// w = cypher.NewEncryptedResponseWriter(w, key)

		next.ServeHTTP(w, r)
	})
}
