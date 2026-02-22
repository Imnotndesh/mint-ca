package setup

import (
	"errors"
	"fmt"

	"mint-ca/internal/storage"
)

// ErrAlreadyReady is returned when a setup action is attempted on a server
// that has already completed setup.
var ErrAlreadyReady = errors.New("setup: server is already configured")

// ErrNotInSetup is returned when a setup action requires setup mode but
// the server is not currently in it.
var ErrNotInSetup = errors.New("setup: server is not in setup mode")

// Transition validates a state transition and returns an error if it is not
// a legal move. Valid transitions: uninitialized→setup, setup→ready.
func Transition(from, to storage.SetupState) error {
	switch {
	case from == storage.StateUninitialized && to == storage.StateSetup:
		return nil
	case from == storage.StateSetup && to == storage.StateReady:
		return nil
	default:
		return fmt.Errorf("setup: invalid state transition %s → %s", from, to)
	}
}
