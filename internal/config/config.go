package config

import (
	"io/ioutil"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Port       int           `yaml:"port"`
	Expiration time.Duration `yaml:"token_expiration"`
	SecretEnv  string        `yaml:"secret_env"`
	CertPath   string        `yaml:"cert_path"`
	KeyPath    string        `yaml:"key_path"`
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

	return cfg, nil
}
