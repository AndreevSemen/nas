package db

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"

	"github.com/AndreevSemen/nas/internal/config"
)

var (
	ErrEmptyResponse = errors.New("got empty response from db")
	ErrUnauthorized  = errors.New("bad login or password")
)

type SQLiteDB struct {
	db *sql.DB
}

func NewSQLiteDB(cfg config.Config) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", cfg.Database.SQLiteDB)
	if err != nil {
		return nil, err
	}

	sqliteDB := &SQLiteDB{
		db: db,
	}

	return sqliteDB, nil
}

func (db *SQLiteDB) IsLoginExists(login string) (bool, error) {
	rows, err := db.db.Query(`SELECT count(login) FROM logins WHERE login=?`, login)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	if !rows.Next() {
		return false, ErrEmptyResponse
	}

	var count int
	if err := rows.Scan(&count); err != nil {
		return false, err
	}

	exists := count != 0
	return exists, nil
}

func (db *SQLiteDB) SetPassword(login, password string) error {
	_, err := db.db.Exec(`INSERT INTO logins (login, password) VALUES (?, ?)`, login, password)
	return err
}

func (db *SQLiteDB) ComparePassword(login, password string) (bool, error) {
	rows, err := db.db.Query(`SELECT (CASE password WHEN ? THEN 'ok' ELSE 'fail' END) FROM logins WHERE login=?;`, password, login)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	if !rows.Next() {
		return false, nil
	}

	var checkResult string
	if err := rows.Scan(&checkResult); err != nil {
		return false, err
	}

	equal := checkResult == "ok"
	return equal, nil
}

func (db *SQLiteDB) GetSharedKey(alicePubKey []byte) (sharedKey []byte, ok bool, err error) {
	rows, err := db.db.Query(`SELECT shared_key FROM shared_keys WHERE alice_public_key=?`)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, false, nil
	}

	if err := rows.Scan(&sharedKey); err != nil {
		return nil, false, err
	}

	return sharedKey, true, nil
}

func (db *SQLiteDB) SetSharedKey(alicePubKey, sharedKey []byte) error {
	_, err := db.db.Exec(`INSERT INTO shared_keys (alice_public_key, shared_key) VALUES (?, ?)`, alicePubKey, sharedKey)
	return err
}
