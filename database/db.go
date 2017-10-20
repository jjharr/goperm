package database

import (
	"fmt"
	"database/sql"
	"github.com/jmoiron/sqlx"
	"regexp"
	"strings"
	"errors"
)

type QueryExecFunc func(*sql.Tx) (sql.Result, error)

func Exec1Row(db *sqlx.DB, query string, args ...interface{}) error {


	result, err := db.Exec(query, args...)

	if err != nil {
		return err
	}

	num, err := result.RowsAffected()
	if err != nil {
		return err
	} else if num != 1 {
		return fmt.Errorf("Updated %s rows: %s", num, query)
	}

	return nil
}

// Takes a query and a map of all parameters to that query. Returns query, args, nil
func ProcessNamedQueryForIn(namedQuery string, namedParams map[string]interface{}) (string, []interface{}, error) {
	randomStr := "91d63f094b5bcbebdb22a8b23d991ca0"
	namedQuery = regexp.MustCompile(`:\d`).ReplaceAllStringFunc(namedQuery, func(s string) string {
		return strings.Replace(s, ":", randomStr, 1)
	})

	query, args, err := sqlx.Named(namedQuery, namedParams)
	if err != nil {
		return ``, nil, fmt.Errorf("Failed to interpolate named params: sql=%s, params=%#v", query, namedParams)
	}
	query = strings.Replace(query, randomStr, ":", -1)

	// TODO - This fails if passed an empty slice. It should fail more gracefully, like with a sentinel error

	query, args, err = sqlx.In(query, args...)
	if err != nil {
		return ``, nil, fmt.Errorf("Failed to process IN params: sql=%s, params=%#v", query, namedParams)
	}

	query = sqlx.Rebind(sqlx.DOLLAR, query)
	if err != nil {
		return ``, nil, fmt.Errorf("Failed to rebind query: sql=%s, params=%#v", query, namedParams)
	}

	return query, args, nil
}

// TxExecFunc is a helper methods that returns a function to be used in transactions
func TxExecFunc(query string, args ...interface{}) QueryExecFunc {
	return func(tx *sql.Tx) (sql.Result, error) {
		return tx.Exec(query, args...)
	}
}

// transact executes a transaction compriles of QueryExecFunc
func Transact(db *sqlx.DB, txFuncs []QueryExecFunc) (err error) {

	tx, err := db.Begin()
	if err != nil {
		err = errors.New("Transaction Begin failed;")
		return
	}

	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr == nil {
				err = errors.New("Transaction failed. Rollback executed")
			} else {
				err = fmt.Errorf("Rollback initialized because: %s", err.Error())
			}
			return
		}
		err = tx.Commit()
	}()

	for _, q := range txFuncs {
		if _, err = q(tx); err != nil {
			err = errors.New("Transact failed to execute query")
			return
		}
	}

	return
}