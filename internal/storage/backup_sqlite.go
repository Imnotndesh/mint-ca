package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// sqliteDSN builds the connection string used by newSQLiteStore. Shared by
// Backup/Restore so a reopened handle matches the original settings.
func sqliteDSN(dsn string) string {
	return fmt.Sprintf("%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000&_synchronous=NORMAL", dsn)
}

// Backup streams a consistent snapshot of the SQLite database using
// VACUUM INTO (safe with WAL and concurrent readers).
func (s *sqliteStore) Backup(ctx context.Context) ([]byte, error) {
	tmp, err := os.CreateTemp("", "mintca-backup-*.db")
	if err != nil {
		return nil, fmt.Errorf("sqlite: backup: %w", err)
	}
	path := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(path) // VACUUM INTO requires the target to not exist
	defer os.Remove(path)

	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return nil, fmt.Errorf("sqlite: backup: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: backup read: %w", err)
	}
	return data, nil
}

// Restore replaces the on-disk database with data (a valid SQLite file) and
// reopens the connection in-process, so no restart is required. Only supported
// for file-backed databases.
func (s *sqliteStore) Restore(ctx context.Context, data []byte) error {
	if s.dsn == "" || s.dsn == ":memory:" || strings.Contains(s.dsn, "mode=memory") {
		return fmt.Errorf("sqlite: restore is not supported for in-memory databases")
	}
	// Validate the uploaded bytes open as a SQLite database.
	verify, err := os.CreateTemp("", "mintca-verify-*.db")
	if err != nil {
		return fmt.Errorf("sqlite: restore: %w", err)
	}
	vpath := verify.Name()
	_ = verify.Close()
	defer os.Remove(vpath)
	if err := os.WriteFile(vpath, data, 0o600); err != nil {
		return fmt.Errorf("sqlite: restore write temp: %w", err)
	}
	vdb, err := sql.Open("sqlite3", vpath+"?_foreign_keys=on")
	if err != nil {
		return fmt.Errorf("sqlite: restore invalid database: %w", err)
	}
	var n int
	if err := vdb.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		_ = vdb.Close()
		return fmt.Errorf("sqlite: restore: not a valid SQLite database: %w", err)
	}
	_ = vdb.Close()

	// Close the live handle, replace the file, reopen with the same settings.
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("sqlite: restore close: %w", err)
	}
	if err := os.WriteFile(s.dsn, data, 0o600); err != nil {
		return fmt.Errorf("sqlite: restore write: %w", err)
	}
	db, err := sql.Open("sqlite3", sqliteDSN(s.dsn))
	if err != nil {
		return fmt.Errorf("sqlite: restore reopen: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return fmt.Errorf("sqlite: restore ping: %w", err)
	}
	s.db = db
	if err := s.Migrate(ctx); err != nil {
		return fmt.Errorf("sqlite: restore migrate: %w", err)
	}
	return nil
}
