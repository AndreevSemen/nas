package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/AndreevSemen/nas/internal/client"
	"github.com/AndreevSemen/nas/internal/config"
)

var (
	configPath = flag.String("config", "", "path to config file")
	remoteDir  = flag.String("remote", "", "directory which read from NAS")
	localDir   = flag.String("local", "", "directory to write files from NAS")
	action     = flag.String("action", "", "one of actions: download/sync")

	logger = logrus.WithField("logging-entity", "main")
)

func init() {
	flag.Parse()
}

func main() {
	cfg, err := config.ParseClientConfig(*configPath)
	if err != nil {
		logger.Fatalf("parse config: %s", err)
	}

	cli, err := client.NewClient(cfg, cfg.Login, cfg.Password)
	if err != nil {
		logger.Fatalf("create client: %s", err)
	} else {
		logger.Infof("client successfully created.")
	}

	switch *action {
	case "download":
		logger.Info("downloading...")
		if err := os.RemoveAll(filepath.Join(*localDir, *remoteDir)); err != nil {
			logger.Fatalf("clear before downloading: %s", err)
		}
		if err := cli.DownloadStorage(*remoteDir, *localDir); err != nil {
			logger.Fatalf("download failed: %s", err)
		} else {
			logger.Info("successfully downloaded.")
		}

	case "sync":
		logger.Info("syncing...")
		if err := cli.SyncStorage(*localDir, *remoteDir); err != nil {
			logger.Fatalf("sync failed: %s", err)
		} else {
			logger.Info("successfully synced.")
		}

	default:
		logger.Fatalf("bad action: '%s'", *action)
	}

}
