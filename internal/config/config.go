package config

import (
	"io/ioutil"
	"os"
	"regexp"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

var (
	ErrBadVirtualStorageName   = errors.New("bad virtual storage name")
	ErrRealPathIsNotADirectory = errors.New("real path is not a directory")
	ErrRealPathIsNotExists     = errors.New("real path is not exists")

	virtualStorageNameRegexp = regexp.MustCompile(`^([a-zA-Z0-9-_])+$`)
)

type Config struct {
	Server struct {
		Port       int           `yaml:"port"`
		Expiration time.Duration `yaml:"jwtTokenExpiration"`
		Secret     string        `yaml:"jwtSecret"`
		CertPath   string        `yaml:"sslCertPath"`
		KeyPath    string        `yaml:"sslKeyPath"`
	} `yaml:"fileserver"`
	VirtualStorages map[string]string `yaml:"virtualStorages"`
}

func Parse(path string) (Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		err = errors.Wrap(err, "read config file")
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		err = errors.Wrap(err, "parse config file")
		return Config{}, err
	}

	for virtualStorage, realStorage := range cfg.VirtualStorages {
		if !virtualStorageNameRegexp.MatchString(virtualStorage) {
			return Config{}, ErrBadVirtualStorageName
		}

		info, err := os.Stat(realStorage)
		if err == nil {
			if !info.IsDir() {
				return Config{}, ErrRealPathIsNotADirectory
			}
		} else if os.IsNotExist(err) {
			return Config{}, ErrRealPathIsNotExists
		} else {
			return Config{}, err
		}
	}

	return cfg, nil
}
