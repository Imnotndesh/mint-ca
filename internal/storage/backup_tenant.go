package storage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// tenantBackup is a portable, tenant-scoped snapshot: the tenant row plus all
// rows of the tenant-owned tables it depends on. Key material is carried as
// base64 so binary columns round-trip exactly.
type tenantBackup struct {
	Format   string               `json:"format"`
	Version  int                  `json:"version"`
	TenantID string               `json:"tenant_id"`
	Tables   map[string]tableData `json:"tables"`
}

type tableData struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// tenantTableScopes lists tenant-owned tables in FK-safe import order, each
// with the SELECT selecting that tenant's rows. The tenant row is exported
// separately (see tenantBackup.TenantID).
var tenantTableScopes = []struct {
	name string
	sel  string
}{
	{"profiles", "SELECT * FROM profiles WHERE tenant_id = ?"},
	{"policies", "SELECT * FROM policies WHERE tenant_id = ?"},
	{"certificate_authorities", "SELECT * FROM certificate_authorities WHERE tenant_id = ?"},
	{"ssh_certificate_authorities", "SELECT * FROM ssh_certificate_authorities WHERE tenant_id = ?"},
	{"provisioners", "SELECT * FROM provisioners WHERE tenant_id = ?"},
	{"csr_approval_rules", "SELECT * FROM csr_approval_rules WHERE provisioner_id IN (SELECT id FROM provisioners WHERE tenant_id = ?)"},
	{"eab_credentials", "SELECT * FROM eab_credentials WHERE provisioner_id IN (SELECT id FROM provisioners WHERE tenant_id = ?)"},
	{"api_keys", "SELECT * FROM api_keys WHERE tenant_id = ?"},
	{"certificates", "SELECT * FROM certificates WHERE ca_id IN (SELECT id FROM certificate_authorities WHERE tenant_id = ?)"},
	{"ssh_certificates", "SELECT * FROM ssh_certificates WHERE ca_id IN (SELECT id FROM ssh_certificate_authorities WHERE tenant_id = ?)"},
}

func isBinaryType(name string) bool {
	n := strings.ToUpper(name)
	return strings.Contains(n, "BLOB") || strings.Contains(n, "BYTEA")
}

// exportTable returns the column names and JSON-safe rows for one query. Text
// and numeric columns become strings (SQLite affinity re-coerces on import);
// binary columns become {"b64": ...} objects so they survive JSON intact.
func exportTable(ctx context.Context, db *sql.DB, query string, args ...any) (tableData, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return tableData{}, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return tableData{}, err
	}
	cts, err := rows.ColumnTypes()
	if err != nil {
		return tableData{}, err
	}
	binary := make([]bool, len(cols))
	for i, ct := range cts {
		binary[i] = isBinaryType(ct.DatabaseTypeName())
	}
	td := tableData{Columns: cols, Rows: [][]any{}}
	for rows.Next() {
		holders := make([]any, len(cols))
		blobs := make([][]byte, len(cols))
		for i := range cols {
			if binary[i] {
				holders[i] = &blobs[i]
			} else {
				holders[i] = new(sql.RawBytes)
			}
		}
		if err := rows.Scan(holders...); err != nil {
			return tableData{}, err
		}
		vals := make([]any, len(cols))
		for i := range cols {
			if binary[i] {
				if blobs[i] == nil {
					vals[i] = nil
				} else {
					vals[i] = map[string]string{"b64": base64.StdEncoding.EncodeToString(blobs[i])}
				}
			} else {
				raw := *(holders[i].(*sql.RawBytes))
				if raw == nil {
					vals[i] = nil
				} else {
					vals[i] = string(raw)
				}
			}
		}
		td.Rows = append(td.Rows, vals)
	}
	return td, rows.Err()
}

// TenantExport snapshots one tenant and all of its owned rows.
func (s *sqliteStore) TenantExport(ctx context.Context, tenantID string) ([]byte, error) {
	id, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: tenant export: invalid tenant id: %w", err)
	}
	t, err := s.GetTenant(ctx, id)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("sqlite: tenant export: tenant %s not found", tenantID)
	}
	tb := tenantBackup{Format: "mintca-tenant-export", Version: 1, TenantID: tenantID, Tables: map[string]tableData{}}
	// The tenant row itself (needed to recreate the tenant on import).
	td0, err := exportTable(ctx, s.db, "SELECT * FROM tenants WHERE id = ?", tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: tenant export tenants: %w", err)
	}
	tb.Tables["tenants"] = td0
	for _, sc := range tenantTableScopes {
		td, err := exportTable(ctx, s.db, sc.sel, tenantID)
		if err != nil {
			return nil, fmt.Errorf("sqlite: tenant export %s: %w", sc.name, err)
		}
		tb.Tables[sc.name] = td
	}
	return json.Marshal(tb)
}

// TenantRestore inserts a previously exported tenant (and its rows) into this
// instance. The tenant keeps its original id so all cross-references remain
// valid; restoring a tenant id that already exists is an error.
func (s *sqliteStore) TenantRestore(ctx context.Context, data []byte) (*Tenant, error) {
	var tb tenantBackup
	if err := json.Unmarshal(data, &tb); err != nil {
		return nil, fmt.Errorf("sqlite: tenant restore: invalid backup: %w", err)
	}
	if tb.Format != "mintca-tenant-export" {
		return nil, fmt.Errorf("sqlite: tenant restore: unexpected format %q", tb.Format)
	}
	id, err := uuid.Parse(tb.TenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: tenant restore: invalid tenant id: %w", err)
	}
	if existing, _ := s.GetTenant(ctx, id); existing != nil {
		return nil, fmt.Errorf("sqlite: tenant restore: tenant %s already exists", tb.TenantID)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sqlite: tenant restore begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys=on"); err != nil {
		return nil, fmt.Errorf("sqlite: tenant restore pragma: %w", err)
	}

	// Insert the tenant row first (from the exported tenants table).
	if row, ok := firstRow(tb.Tables, "tenants"); ok {
		if err := insertRow(ctx, tx, "tenants", tb.Tables["tenants"].Columns, row); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("sqlite: tenant restore: backup missing tenants row")
	}
	for _, sc := range tenantTableScopes {
		td, ok := tb.Tables[sc.name]
		if !ok {
			continue
		}
		for _, row := range td.Rows {
			if err := insertRow(ctx, tx, sc.name, td.Columns, row); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sqlite: tenant restore commit: %w", err)
	}
	return s.GetTenant(ctx, id)
}

// firstRow is a tiny helper for the single-row tenants table.
func firstRow(tables map[string]tableData, name string) ([]any, bool) {
	td, ok := tables[name]
	if !ok || len(td.Rows) == 0 {
		return nil, false
	}
	return td.Rows[0], true
}

func insertRow(ctx context.Context, tx *sql.Tx, table string, cols []string, row []any) error {
	placeholders := make([]string, len(cols))
	args := make([]any, len(cols))
	for i := range cols {
		placeholders[i] = "?"
		if i < len(row) {
			args[i] = decodeValue(row[i])
		}
	}
	q := "INSERT INTO " + table + " (" + strings.Join(cols, ",") + ") VALUES (" + strings.Join(placeholders, ",") + ")"
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("sqlite: tenant restore insert %s: %w", table, err)
	}
	return nil
}

// decodeValue converts a JSON value back to a driver value.
func decodeValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case map[string]any:
		if b64, ok := t["b64"].(string); ok {
			b, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				return b
			}
		}
		return nil
	case map[string]string:
		if b64, ok := t["b64"]; ok {
			b, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				return b
			}
		}
		return nil
	default:
		return v
	}
}
