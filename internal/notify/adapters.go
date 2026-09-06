package notify

import (
	"context"

	"mint-ca/internal/events"
	"mint-ca/internal/renewal"
)

type EventEmitter struct {
	Manager *Manager
}

func (e EventEmitter) Emit(ev events.Event) {
	e.Manager.Notify(ev.Type, ev.Data)
}

type RenewalDeliverer struct {
	Manager *Manager
}

func (d RenewalDeliverer) Deliver(_ context.Context, n renewal.Notice) error {
	d.Manager.Notify(CategoryCertExpiring, map[string]any{
		"cert_id":    n.CertID,
		"ca_id":      n.CAID,
		"serial":     n.Serial,
		"subject_cn": n.SubjectCN,
		"expires_at": n.ExpiresAt,
		"days_left":  n.DaysLeft,
		"escrowed":   n.Escrowed,
	})
	return nil
}
