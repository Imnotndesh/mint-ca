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
