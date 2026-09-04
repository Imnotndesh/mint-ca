package handlers

import (
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// tenantOwns reports whether a resource (whose TenantID is resourceTenantID;
// uuid.Nil means legacy/unset) belongs to caller. callerTenantID == nil means
// platform admin (sees everything). Legacy rows (uuid.Nil owner) are treated
// as belonging to the default tenant so pre-upgrade single-tenant data stays
// reachable by a default-tenant-scoped key.
func tenantOwns(resourceTenantID uuid.UUID, callerTenantID *uuid.UUID) bool {
	if callerTenantID == nil {
		return true
	}
	if resourceTenantID == uuid.Nil {
		return *callerTenantID == storage.DefaultTenantID
	}
	return resourceTenantID == *callerTenantID
}

// normalizedTenant maps a legacy/nil tenant watermark to the default tenant so
// two server-side resources (no caller tenant involved) compare deterministically.
func normalizedTenant(id uuid.UUID) uuid.UUID {
	if id == uuid.Nil {
		return storage.DefaultTenantID
	}
	return id
}

// sameTenant reports whether two resources (CA vs provisioner, etc.) share a
// tenant after normalizing the legacy nil watermark.
func sameTenant(a, b uuid.UUID) bool {
	return normalizedTenant(a) == normalizedTenant(b)
}
