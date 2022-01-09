package db

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"

	"github.com/AndreevSemen/nas/internal/config"
)

var (
	ErrEmptyResponse = errors.New("got empty response from db")
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
		return false, ErrEmptyResponse
	}

	var checkResult string
	if err := rows.Scan(&checkResult); err != nil {
		return false, err
	}

	equal := checkResult == "ok"
	return equal, nil
}
