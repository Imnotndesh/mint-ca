package storage

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Backup writes a pg_dump custom-format archive of the whole database to
// memory. Requires the pg_dump binary on PATH.
func (s *postgresStore) Backup(ctx context.Context) ([]byte, error) {
	pgdump, err := exec.LookPath("pg_dump")
	if err != nil {
		return nil, fmt.Errorf("postgres: backup requires the pg_dump binary on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, pgdump, "--format=custom", "--no-owner", "--dbname", s.dsn)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("postgres: pg_dump failed: %w: %s", err, errBuf.String())
	}
	return out.Bytes(), nil
}

// Restore applies a pg_dump archive (custom format) to the database, replacing
// existing objects. Requires the pg_restore binary on PATH. The connection is
// not closed; pg_restore operates on the live database (safe for a maintenance
// action on an otherwise idle instance).
func (s *postgresStore) Restore(ctx context.Context, data []byte) error {
	pgrestore, err := exec.LookPath("pg_restore")
	if err != nil {
		return fmt.Errorf("postgres: restore requires the pg_restore binary on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, pgrestore, "--clean", "--if-exists", "--no-owner", "--dbname", s.dsn)
	cmd.Stdin = bytes.NewReader(data)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("postgres: pg_restore failed: %w: %s", err, errBuf.String())
	}
	return nil
}
