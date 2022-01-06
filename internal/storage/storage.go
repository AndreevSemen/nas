package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

var (
	ErrFileNotExists    = errors.New("file not found")
	ErrFileExists       = errors.New("file already exists")
	ErrFileIsADirectory = errors.New("file is a directory")
	ErrPermissionDenied = errors.New("permission denied")
)

type Storage struct {
	sharedDir string
}

func NewStorage(dir string) *Storage {
	return &Storage{
		sharedDir: dir,
	}
}

func (s *Storage) Get(path string) (io.ReadCloser, error) {
	path = filepath.Join(s.sharedDir, path)

	stat, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, ErrFileNotExists
	} else if os.IsPermission(err) {
		return nil, ErrPermissionDenied
	} else if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("get stat of file '%s'", path))
		return nil, err
	}

	if stat.IsDir() {
		return nil, ErrFileIsADirectory
	}

	rc, err := os.Open(path)
	if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("open file '%s'", path))
		return nil, err
	}

	return rc, nil
}

func (s *Storage) PutFile(path string, rc io.ReadCloser) error {
	if rc == nil {
		panic("got nil io.ReadCloser")
	}
	defer rc.Close()

	path = filepath.Join(s.sharedDir, path)

	_, err := os.Stat(path)
	if err == nil {
		return ErrFileExists
	} else if os.IsPermission(err) {
		return ErrPermissionDenied
	} else if err != nil && !os.IsNotExist(err) {
		err = errors.Wrap(err, fmt.Sprintf("get stat of file '%s'", path))
		return err
	}

	f, err := os.Create(path)
	if os.IsPermission(err) {
		return ErrPermissionDenied
	} else if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("create file '%s'", path))
		return err
	}

	buf := [512]byte{}
	if _, err = io.CopyBuffer(f, rc, buf[:]); err != nil {
		err = errors.Wrap(err, "copy data to file")
		return err
	}

	return nil
}

func (s *Storage) Delete(path string) error {
	path = filepath.Join(s.sharedDir, path)

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return ErrFileNotExists
	} else if os.IsPermission(err) {
		return ErrPermissionDenied
	} else if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("get stat of file '%s'", path))
		return err
	}

	err = os.RemoveAll(path)
	if os.IsPermission(err) {
		return ErrPermissionDenied
	} else if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("remove file/dir '%s'", path))
		return err
	}

	return nil
}
