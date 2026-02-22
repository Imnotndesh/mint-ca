package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"mint-ca/internal/storage"
)

const bootstrapKeyName = "__bootstrap__"

// BootstrapKey holds the plaintext key printed to stdout once on first boot.
type BootstrapKey struct {
	Raw string
	ID  uuid.UUID
}

// GenerateBootstrapKey creates a temporary API key scoped only to setup
// endpoints, stores its hash, and returns the plaintext for printing.
func GenerateBootstrapKey(ctx context.Context, store storage.Store) (*BootstrapKey, error) {
	existing, err := store.GetAPIKeyByName(ctx, bootstrapKeyName)
	if err != nil {
		return nil, fmt.Errorf("setup: check existing bootstrap key: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf(
			"setup: a bootstrap key already exists from a previous boot — " +
				"check your container logs for the original key. " +
				"If you cannot find it, delete /data/mint-ca.db and start fresh",
		)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("setup: generate bootstrap key: %w", err)
	}
	rawKey := "mca_" + hex.EncodeToString(raw)

	sum := sha256.Sum256([]byte(rawKey))
	hash := hex.EncodeToString(sum[:])

	id := uuid.New()
	k := &storage.APIKey{
		ID:        id,
		Name:      bootstrapKeyName,
		KeyHash:   hash,
		Scopes:    []string{"setup"},
		CreatedAt: time.Now().UTC(),
	}
	if err := store.CreateAPIKey(ctx, k); err != nil {
		return nil, fmt.Errorf("setup: store bootstrap key: %w", err)
	}

	return &BootstrapKey{Raw: rawKey, ID: id}, nil
}

// DeleteBootstrapKey removes the bootstrap key. Called at end of setup.
func DeleteBootstrapKey(ctx context.Context, store storage.Store) error {
	existing, err := store.GetAPIKeyByName(ctx, bootstrapKeyName)
	if err != nil {
		return fmt.Errorf("setup: find bootstrap key: %w", err)
	}
	if existing == nil {
		return nil
	}
	if err := store.DeleteAPIKey(ctx, existing.ID); err != nil {
		return fmt.Errorf("setup: delete bootstrap key: %w", err)
	}
	slog.Info("setup: bootstrap key deleted")
	return nil
}

// PrintBootstrapKey writes the bootstrap key to stdout in a visible block.
func PrintBootstrapKey(key *BootstrapKey) {
	border := "═══════════════════════════════════════════════════════════════"
	fmt.Printf("\n%s\n", border)
	fmt.Printf("  mint-ca SETUP MODE\n\n")
	fmt.Printf("  Bootstrap API Key (printed ONCE — save it now):\n\n")
	fmt.Printf("  %s\n\n", key.Raw)
	fmt.Printf("  Complete setup:\n")
	fmt.Printf("    POST /setup/root-ca   — create the root CA\n")
	fmt.Printf("    POST /setup/api-key   — create your permanent key\n\n")
	fmt.Printf("  After /setup/api-key completes:\n")
	fmt.Printf("    • This bootstrap key is permanently deleted\n")
	fmt.Printf("    • The server restarts its listener with TLS\n")
	fmt.Printf("%s\n\n", border)
}
