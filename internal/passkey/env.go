package passkey

import (
	"os"
	"strings"
	"time"
)

// RequiredForEnv names the MINT_PASSKEY_REQUIRED_FOR policy values.
const (
	RequiredOff      = "off"
	RequiredHighRisk = "high_risk"
	RequiredAll      = "all"
)

// ConfigFromEnv reads passkey settings from the environment.
//
//	MINT_PASSKEY_ENABLED      enable the passkey endpoints (default false)
//	MINT_PASSKEY_RPID         WebAuthn relying-party id (e.g. ca.internal)
//	MINT_PASSKEY_ORIGINS      comma-separated allowed origins (default https://<rpid>)
//	MINT_PASSKEY_REQUIRED_FOR off | high_risk | all  (default off)
//	MINT_PASSKEY_STEPUP_TTL   step-up session TTL (default 15m)
func ConfigFromEnv() (Config, bool) {
	enabled := truthy(os.Getenv("MINT_PASSKEY_ENABLED"))
	cfg := Config{
		RPDisplayName: strings.TrimSpace(os.Getenv("MINT_PASSKEY_RP_DISPLAY_NAME")),
		RPID:          strings.TrimSpace(os.Getenv("MINT_PASSKEY_RPID")),
		StepUpTTL:     15 * time.Minute,
	}
	if raw := strings.TrimSpace(os.Getenv("MINT_PASSKEY_ORIGINS")); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if o = strings.TrimSpace(o); o != "" {
				cfg.RPOrigins = append(cfg.RPOrigins, o)
			}
		}
	}
	if cfg.RPID != "" && len(cfg.RPOrigins) == 0 {
		cfg.RPOrigins = []string{"https://" + cfg.RPID}
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "mint-ca"
	}
	return cfg, enabled
}

// RequiredFromEnv returns the configured step-up policy (default "off").
func RequiredFromEnv() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MINT_PASSKEY_REQUIRED_FOR"))) {
	case RequiredHighRisk:
		return RequiredHighRisk
	case RequiredAll:
		return RequiredAll
	default:
		return RequiredOff
	}
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
