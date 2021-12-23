package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/AndreevSemen/nas/internal/config"
	"github.com/AndreevSemen/nas/internal/server"
	"github.com/sirupsen/logrus"
)

var (
	configPath = flag.String("config", "", "config path")
)

func main() {
	flag.Parse()
	cfg, err := config.Parse(*configPath)
	if err != nil {
		logrus.Fatalf("parse config: %s", err)
	}

	fs, err := server.NewSFileServer(cfg)
	if err != nil {
		logrus.Fatalf("create file server: %s", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		logrus.Fatalf("listen port %d: %s", cfg.Port, err)
	}

	fs.Start(lis)
}
