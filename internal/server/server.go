package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/schema"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/AndreevSemen/nas/internal/auth"
	"github.com/AndreevSemen/nas/internal/config"
	"github.com/AndreevSemen/nas/internal/db"
	"github.com/AndreevSemen/nas/internal/storage"
	"github.com/AndreevSemen/nas/internal/structures"
)

var (
	ErrNoSecretEnv            = errors.New("env with secret not exists")
	ErrBadVirtualPath         = errors.New("bad virtual path")
	ErrVirtualStorageNotFound = errors.New("virtual storage not found")

	ErrNoPublicKey        = errors.New("no public key")
	ErrBadPublicKeyFormat = errors.New("bad public key format")
	ErrBadMethod          = errors.New("bad HTTP method")
	ErrBadQueryParams     = errors.New("bad query params")
)

type FileServer struct {
	server *http.Server
	auth   *auth.AuthManager
	db     *db.SQLiteDB
	stores map[string]*storage.Storage
}

func NewSFileServer(cfg config.Config) (*FileServer, error) {
	db, err := db.NewSQLiteDB(cfg)
	if err != nil {
		return nil, err
	}

	fs := &FileServer{
		server: &http.Server{},
		auth:   auth.NewAuthManager(cfg, cfg.Server.Secret, db),
		db:     db,
		stores: make(map[string]*storage.Storage, len(cfg.VirtualStorages)),
	}

	for virtualRoot, realRoot := range cfg.VirtualStorages {
		fs.stores[virtualRoot] = storage.NewStorage(realRoot, virtualRoot)
	}

	return fs, nil
}

func (fs *FileServer) Start(cfg config.Config, lis net.Listener) {
	cypherMux := http.NewServeMux()
	// mux.Handle("/sign_up", http.HandlerFunc(fs.handleSignUp))
	cypherMux.Handle("/sign_in", http.HandlerFunc(fs.handleSignIn))
	cypherMux.Handle("/", fs.middlewareAuthz(http.HandlerFunc(fs.handleFilesystem)))

	plainMux := http.NewServeMux()
	plainMux.Handle("/generate_shared_key", http.HandlerFunc(fs.generateSharedKey))
	plainMux.Handle("/", fs.middlewareCypher(cypherMux))

	fs.server.Handler = commonMiddleware(plainMux)

	logrus.Info("file server started.")
	if err := fs.server.ServeTLS(lis, cfg.Server.CertPath, cfg.Server.KeyPath); err == http.ErrServerClosed {
		logrus.Info("file server successfully stopped.")
	} else {
		logrus.Errorf("file server stopped: %s", err)
	}
}

// func (fs *FileServer) handleSignUp(w http.ResponseWriter, r *http.Request) {
// 	defer r.Body.Close()

// 	d := json.NewDecoder(r.Body)
// 	var creds structures.Credentials
// 	if err := d.Decode(&creds); err != nil {
// 		responseWithError(w, "bad credentials format", http.StatusBadRequest)
// 		return
// 	}

// 	err := fs.auth.SignUp(creds.Login, creds.Password)
// 	switch err {
// 	case nil:
// 		responseWithSuccess(w)

// 	case auth.ErrBadLogin:
// 		responseWithError(w, err.Error(), http.StatusBadRequest)

// 	case auth.ErrBadPassword:
// 		responseWithError(w, err.Error(), http.StatusBadRequest)

// 	case auth.ErrLoginExists:
// 		responseWithError(w, err.Error(), http.StatusConflict)

// 	default:
// 		logrus.WithField("logging-entity", "auth/sign_up").Error(err.Error())
// 		responseWithError(w, "internal server error", http.StatusInternalServerError)
// 	}
// }

func (fs *FileServer) handleSignIn(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithField("logging-entity", "auth/sign_in")

	d := json.NewDecoder(r.Body)
	var creds structures.Credentials
	if err := d.Decode(&creds); err != nil {
		responseWithError(logger, w, "bad credentials format", http.StatusBadRequest)
		return
	}

	token, err := fs.auth.SignIn(creds.Login, creds.Password)
	switch err {
	case nil:
		w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", token))
		responseWithSuccess(w)

	case auth.ErrBadCreds:
		responseWithError(logger, w, err.Error(), http.StatusUnauthorized)

	default:
		logger.Error(err.Error())
		responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
	}
}

func (fs *FileServer) middlewareAuthz(next http.Handler) http.Handler {
	logger := logrus.WithField("logging-entity", "auth/check-token")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		splittedHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(splittedHeader) != 2 || (splittedHeader[0] != "Bearer") {
			responseWithError(logger, w, "invalid access token format", http.StatusUnauthorized)
			return
		}
		token := splittedHeader[1]

		err := fs.auth.Authz(token)
		switch err {
		case nil:
			next.ServeHTTP(w, r)

		case auth.ErrBadToken:
			responseWithError(logger, w, err.Error(), http.StatusUnauthorized)

		default:
			logger.Error(err.Error())
			responseWithError(logger, w, auth.ErrBadToken.Error(), http.StatusUnauthorized)
		}
	})
}

func (fs *FileServer) handleFilesystem(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithField("logging-entity", "fs")
	// split path like "/<virtualStorageName>/<virtualPath>" into ["<virtualStorageName>", "<virtualPath>"]
	virtualStorageSplit := strings.SplitN(strings.TrimLeft(r.URL.Path, "/"), "/", 2)

	var virtualStorage, filePath string
	if len(virtualStorageSplit) == 2 {
		virtualStorage = virtualStorageSplit[0]
		filePath = virtualStorageSplit[1]
	} else if len(virtualStorageSplit) == 1 {
		virtualStorage = virtualStorageSplit[0]
		filePath = "/"
	} else {
		responseWithError(logger, w, ErrBadVirtualPath.Error(), http.StatusBadRequest)
		return
	}

	s, ok := fs.stores[virtualStorage]
	if !ok {
		responseWithError(logger, w, ErrVirtualStorageNotFound.Error(), http.StatusNotFound)
		return
	}

	type params struct {
		List  bool `schema:"list"`
		IsDir bool `schema:"is_dir"`
	}

	var p params
	if err := schema.NewDecoder().Decode(&p, r.URL.Query()); err != nil {
		responseWithError(logger, w, ErrBadQueryParams.Error(), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if p.List {
			list, err := s.ListDirectory(filePath)
			switch err {
			case nil:
				responseWithBody(logger, w, list)

			case storage.ErrFileNotExists:
				responseWithError(logger, w, err.Error(), http.StatusNotFound)

			case storage.ErrPermissionDenied:
				responseWithError(logger, w, err.Error(), http.StatusForbidden)

			case storage.ErrCannotListFile:
				responseWithError(logger, w, err.Error(), http.StatusBadRequest)

			default:
				logger.Error(err.Error())
				responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
			}

		} else {
			rc, err := s.Get(filePath)
			switch err {
			case nil:
				defer rc.Close()

				buf := make([]byte, 512)
				if _, err := io.CopyBuffer(w, rc, buf[:]); err != nil {
					responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/octet-stream")

			case storage.ErrFileNotExists:
				responseWithError(logger, w, err.Error(), http.StatusNotFound)

			case storage.ErrFileIsADirectory:
				responseWithError(logger, w, err.Error(), http.StatusBadRequest)

			case storage.ErrPermissionDenied:
				responseWithError(logger, w, err.Error(), http.StatusForbidden)

			default:
				logger.Error(err.Error())
				responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
			}
		}

	case http.MethodPut:
		var err error
		if p.IsDir {
			err = s.Mkdir(filePath)
		} else {
			err = s.PutFile(filePath, r.Body)
		}
		switch err {
		case nil:
			responseWithSuccess(w)

		case storage.ErrFileExists:
			responseWithError(logger, w, err.Error(), http.StatusConflict)

		case storage.ErrPermissionDenied:
			responseWithError(logger, w, err.Error(), http.StatusForbidden)

		default:
			logger.Error(err.Error())
			responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
		}

	case http.MethodDelete:
		err := s.Delete(filePath)
		switch err {
		case nil:
			responseWithSuccess(w)

		case storage.ErrFileNotExists:
			responseWithError(logger, w, err.Error(), http.StatusNotFound)

		case storage.ErrPermissionDenied:
			responseWithError(logger, w, err.Error(), http.StatusForbidden)

		default:
			logger.Error(err.Error())
			responseWithError(logger, w, "internal server error", http.StatusInternalServerError)
		}

	default:
		responseWithError(logger, w, ErrBadMethod, http.StatusMethodNotAllowed)
	}
}

func commonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

func responseWithBody(logger *logrus.Entry, w http.ResponseWriter, body interface{}) {
	data, err := json.Marshal(body)
	if err != nil {
		logrus.Errorf("can't marshal '%#v': %s", err, data)
		fmt.Fprintln(w, `{"error":"500 Internal server error"}`)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logger.Error(string(data))

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func responseWithSuccess(w http.ResponseWriter) {
	w.Write([]byte(`{"result": "success"}`))
}

func responseWithError(logger *logrus.Entry, w http.ResponseWriter, err interface{}, code int) {
	errResp := structures.ErrorResponse{
		Err: err,
	}
	data, err := json.Marshal(errResp)
	if err != nil {
		logrus.Errorf("can't marshal '%#v': %s", err, data)
		fmt.Fprintln(w, `{"error":"500 Internal server error"}`)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logger.Error(string(data))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}
