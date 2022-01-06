package auth

import (
	"fmt"
	"regexp"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/pkg/errors"

	"github.com/AndreevSemen/nas/internal/config"
)

var (
	ErrBadLogin    = errors.New("login has invalid format")
	ErrBadPassword = errors.New("password has invalid format")
	ErrLoginExists = errors.New("user with such login already exists")
	ErrBadCreds    = errors.New("invalid login or password")
	ErrBadToken    = errors.New("bad authorization token")

	loginRegexp    = regexp.MustCompile(`^[a-zA-Z0-9._]{8,20}$`)
	passwordRegexp = regexp.MustCompile(`^[a-zA-Z0-9._]{8,20}$`)
)

type AuthManager struct {
	creds  map[string]string // login -> password
	tokens map[string]struct{}
	cfg    config.Config
	secret string
}

func NewAuthManager(cfg config.Config, secret string) *AuthManager {
	return &AuthManager{
		creds:  make(map[string]string),
		tokens: make(map[string]struct{}),
		cfg:    cfg,
		secret: secret,
	}
}

func (m *AuthManager) SignOn(login, password string) error {
	if !loginRegexp.MatchString(login) {
		return ErrBadLogin
	} else if !passwordRegexp.MatchString(password) {
		return ErrBadPassword
	}

	if _, exists := m.creds[login]; exists {
		return ErrLoginExists
	}
	m.creds[login] = password

	return nil
}

func (m *AuthManager) SignIn(login, password string) (token string, err error) {
	realPassword := m.creds[login]
	if realPassword != password {
		return "", ErrBadCreds
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: jwt.At(time.Now().Add(m.cfg.Server.Expiration)),
		IssuedAt:  jwt.At(time.Now()),
	})

	accessToken, err := t.SignedString([]byte(m.secret))
	if err != nil {
		err = errors.Wrap(err, "sign token")
		return "", err
	}

	return accessToken, nil
}

func (m *AuthManager) Authz(token string) error {
	t, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(fmt.Sprintf("unexpected signing method: %v", t.Header["alg"]))
		}

		return []byte(m.secret), nil
	})
	if err != nil {
		err = errors.Wrap(err, "parse access token")
		return err
	}

	if !t.Valid {
		return ErrBadToken
	}

	return nil
}
