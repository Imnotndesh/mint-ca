package storage

import (
	"fmt"
	"os"
	"strings"
)

// Config holds the storage configuration resolved from environment variables.
type Config struct {
	// Driver is either "sqlite" or "postgres".
	Driver string
	DSN    string
}

// ConfigFromEnv reads MINT_DB_DRIVER and MINT_DB_DSN from the environment
func ConfigFromEnv() (Config, error) {
	driver := strings.ToLower(strings.TrimSpace(os.Getenv("MINT_DB_DRIVER")))
	if driver == "" {
		driver = "sqlite"
	}

	dsn := strings.TrimSpace(os.Getenv("MINT_DB_DSN"))

	switch driver {
	case "sqlite":
		if dsn == "" {
			dsn = "/data/mint-ca.db"
		}
	case "postgres":
		if dsn == "" {
			return Config{}, fmt.Errorf(
				"storage: MINT_DB_DSN must be set when MINT_DB_DRIVER=postgres\n" +
					"  example: postgres://mintca:secret@localhost:5432/mintca?sslmode=require",
			)
		}
	default:
		return Config{}, fmt.Errorf(
			"storage: unsupported MINT_DB_DRIVER %q — valid values are \"sqlite\" and \"postgres\"", driver,
		)
	}

	return Config{Driver: driver, DSN: dsn}, nil
}

// New reads storage configuration from the environment, constructs the
func New() (Store, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}

	switch cfg.Driver {
	case "sqlite":
		return newSQLiteStore(cfg.DSN)
	case "postgres":
		return newPostgresStore(cfg.DSN)
	default:
		// Unreachable after ConfigFromEnv validation, but be explicit.
		return nil, fmt.Errorf("storage: unknown driver %q", cfg.Driver)
	}
}
