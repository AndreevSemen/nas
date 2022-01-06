package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/AndreevSemen/nas/internal/auth"
	"github.com/AndreevSemen/nas/internal/config"
	"github.com/AndreevSemen/nas/internal/storage"
)

var (
	ErrNoSecretEnv            = errors.New("env with secret not exists")
	ErrBadVirtualPath         = errors.New("bad virtual path")
	ErrVirtualStorageNotFound = errors.New("virtual storage not found")
	ErrBadMethod              = errors.New("bad HTTP method")
)

type FileServer struct {
	server *http.Server
	auth   *auth.AuthManager
	stores map[string]*storage.Storage
}

func NewSFileServer(cfg config.Config) (*FileServer, error) {
	secret, exists := os.LookupEnv(cfg.Server.SecretEnv)
	if !exists {
		return nil, ErrNoSecretEnv
	}

	fs := &FileServer{
		server: &http.Server{},
		auth:   auth.NewAuthManager(cfg, secret),
		stores: make(map[string]*storage.Storage, len(cfg.VirtualStorages)),
	}

	for virtualRoot, realRoot := range cfg.VirtualStorages {
		fs.stores[virtualRoot] = storage.NewStorage(realRoot)
	}

	return fs, nil
}

func (fs *FileServer) Start(cfg config.Config, lis net.Listener) {
	mux := http.NewServeMux()
	mux.Handle("/signon", http.HandlerFunc(fs.handleSignOn))
	mux.Handle("/signin", http.HandlerFunc(fs.handleSignIn))
	mux.Handle("/", fs.middlewareAuthz(http.HandlerFunc(fs.handleFilesystem)))

	fs.server.Handler = commonMiddleware(mux)

	logrus.Info("starting file server...")
	if err := fs.server.ServeTLS(lis, cfg.Server.CertPath, cfg.Server.KeyPath); err == http.ErrServerClosed {
		logrus.Info("file server successfully stopped.")
	} else {
		logrus.Errorf("file server stopped: %s", err)
	}
}

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (fs *FileServer) handleSignOn(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	d := json.NewDecoder(r.Body)
	var creds Credentials
	if err := d.Decode(&creds); err != nil {
		responseWithError(w, "bad credentials format", http.StatusBadRequest)
		return
	}

	err := fs.auth.SignOn(creds.Login, creds.Password)
	switch err {
	case nil:
		responseWithSuccess(w)

	case auth.ErrBadLogin:
		responseWithError(w, err.Error(), http.StatusBadRequest)

	case auth.ErrBadPassword:
		responseWithError(w, err.Error(), http.StatusBadRequest)

	case auth.ErrLoginExists:
		responseWithError(w, err.Error(), http.StatusConflict)

	default:
		logrus.WithField("logging-entity", "auth/signon").Error(err.Error())
		responseWithError(w, "internal server error", http.StatusInternalServerError)
	}
}

func (fs *FileServer) handleSignIn(w http.ResponseWriter, r *http.Request) {
	d := json.NewDecoder(r.Body)
	var creds Credentials
	if err := d.Decode(&creds); err != nil {
		responseWithError(w, "bad credentials format", http.StatusBadRequest)
		return
	}

	token, err := fs.auth.SignIn(creds.Login, creds.Password)
	switch err {
	case nil:
		w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", token))
		responseWithSuccess(w)

	case auth.ErrBadCreds:
		responseWithError(w, err.Error(), http.StatusUnauthorized)

	default:
		logrus.WithField("logging-entity", "auth/signin").Error(err.Error())
		responseWithError(w, "internal server error", http.StatusInternalServerError)
	}
}

func (fs *FileServer) middlewareAuthz(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		splittedHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(splittedHeader) != 2 || (splittedHeader[0] != "Bearer") {
			responseWithError(w, "invalid access token format", http.StatusUnauthorized)
			return
		}
		token := splittedHeader[1]

		err := fs.auth.Authz(token)
		switch err {
		case nil:
			next.ServeHTTP(w, r)

		case auth.ErrBadToken:
			responseWithError(w, err.Error(), http.StatusUnauthorized)

		default:
			logrus.WithField("logging-entity", "auth/check-token").Error(err.Error())
			responseWithError(w, auth.ErrBadToken.Error(), http.StatusUnauthorized)
		}
	})
}

func (fs *FileServer) handleFilesystem(w http.ResponseWriter, r *http.Request) {
	// split path like "/<virtualStorageName>/<virtualPath>" into ["<virtualStorageName>", "<virtualPath>"]
	virtualStorageSplit := strings.SplitN(strings.TrimLeft(r.URL.Path, "/"), "/", 2)
	if len(virtualStorageSplit) != 2 {
		responseWithError(w, ErrBadVirtualPath.Error(), http.StatusBadRequest)
		return
	}

	virtualStorage := virtualStorageSplit[0]
	filePath := virtualStorageSplit[1]

	s, ok := fs.stores[virtualStorage]
	if !ok {
		responseWithError(w, ErrVirtualStorageNotFound.Error(), http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rc, err := s.Get(filePath)
		switch err {
		case nil:
			defer rc.Close()

			buf := make([]byte, 512)
			if _, err := io.CopyBuffer(w, rc, buf[:]); err != nil {
				responseWithError(w, "internal server error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/octet-stream")

		case storage.ErrFileNotExists:
			responseWithError(w, err.Error(), http.StatusNotFound)

		case storage.ErrFileIsADirectory:
			responseWithError(w, err.Error(), http.StatusBadRequest)

		case storage.ErrPermissionDenied:
			responseWithError(w, err.Error(), http.StatusForbidden)

		default:
			logrus.WithField("logging-entity", "fs/get").Error(err.Error())
			responseWithError(w, "internal server error", http.StatusInternalServerError)
		}

	case http.MethodPut:
		err := s.PutFile(filePath, r.Body)
		switch err {
		case nil:
			responseWithSuccess(w)

		case storage.ErrFileExists:
			responseWithError(w, err.Error(), http.StatusConflict)

		case storage.ErrPermissionDenied:
			responseWithError(w, err.Error(), http.StatusForbidden)

		default:
			logrus.WithField("logging-entity", "fs/put").Error(err.Error())
			responseWithError(w, "internal server error", http.StatusInternalServerError)
		}

	case http.MethodDelete:
		err := s.Delete(filePath)
		switch err {
		case nil:
			responseWithSuccess(w)

		case storage.ErrFileNotExists:
			responseWithError(w, err.Error(), http.StatusNotFound)

		case storage.ErrPermissionDenied:
			responseWithError(w, err.Error(), http.StatusForbidden)

		default:
			logrus.WithField("logging-entity", "fs/delete").Error(err.Error())
			responseWithError(w, "internal server error", http.StatusInternalServerError)
		}

	default:
		responseWithError(w, ErrBadMethod, http.StatusMethodNotAllowed)
	}
}

func commonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

func responseWithSuccess(w http.ResponseWriter) {
	w.Write([]byte(`{"result": "success"}`))
}

func responseWithError(w http.ResponseWriter, err interface{}, code int) {
	type errorResponse struct {
		Err interface{} `json:"error"`
	}

	errResp := errorResponse{
		Err: err,
	}
	data, err := json.Marshal(errResp)
	if err != nil {
		logrus.Errorf("can't marshal '%#v': %s", err, data)
		fmt.Fprintln(w, `{"error":"500 Internal server error"}`)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(code)
	w.Write(data)
}
