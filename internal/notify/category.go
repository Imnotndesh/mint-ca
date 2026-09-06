package notify

const (
	CategoryCertIssued              = "cert.issued"
	CategoryCertRevoked             = "cert.revoked"
	CategoryCertExpiring            = "cert.expiring"
	CategoryAuthLogin               = "auth.login"
	CategoryAuthTOTP                = "auth.totp"
	CategorySecurityUnusualActivity = "security.unusual_activity"
)

type CategoryDef struct {
	Key            string `json:"key"`
	Label          string `json:"label"`
	Description    string `json:"description"`
	DefaultSubject string `json:"default_subject"`
	DefaultBody    string `json:"default_body"`
}

var Categories = NewRegistry[CategoryDef]()

func RegisterCategory(def CategoryDef) {
	Categories.Register(def.Key, def)
}

func init() {
	RegisterCategory(CategoryDef{
		Key:            CategoryCertIssued,
		Label:          "Certificate issued",
		Description:    "Sent whenever a new certificate is issued.",
		DefaultSubject: "mint-ca: certificate issued ({{.subject_cn}})",
		DefaultBody:    "A certificate was issued.\n\nSubject: {{.subject_cn}}\nSerial: {{.serial}}\n",
	})
	RegisterCategory(CategoryDef{
		Key:            CategoryCertRevoked,
		Label:          "Certificate revoked",
		Description:    "Sent whenever a certificate is revoked.",
		DefaultSubject: "mint-ca: certificate revoked ({{.subject_cn}})",
		DefaultBody:    "A certificate was revoked.\n\nSubject: {{.subject_cn}}\nSerial: {{.serial}}\nReason: {{.reason}}\n",
	})
	RegisterCategory(CategoryDef{
		Key:            CategoryCertExpiring,
		Label:          "Certificate expiring soon",
		Description:    "Sent when a certificate is approaching its expiry.",
		DefaultSubject: "mint-ca: certificate expiring soon ({{.subject_cn}})",
		DefaultBody:    "A certificate is expiring soon.\n\nSubject: {{.subject_cn}}\nSerial: {{.serial}}\nExpires at: {{.expires_at}}\nDays left: {{.days_left}}\n",
	})
	RegisterCategory(CategoryDef{
		Key:            CategoryAuthLogin,
		Label:          "Login notification",
		Description:    "Sent when a user or key authenticates to the server.",
		DefaultSubject: "mint-ca: new login",
		DefaultBody:    "A login occurred.\n\nActor: {{.actor}}\nIP: {{.ip_address}}\nTime: {{.timestamp}}\n",
	})
	RegisterCategory(CategoryDef{
		Key:            CategoryAuthTOTP,
		Label:          "TOTP challenge",
		Description:    "Sent as part of a TOTP-based authentication step.",
		DefaultSubject: "mint-ca: authentication code",
		DefaultBody:    "Your authentication code is: {{.code}}\nIt expires in {{.ttl_seconds}} seconds.\n",
	})
	RegisterCategory(CategoryDef{
		Key:            CategorySecurityUnusualActivity,
		Label:          "Unusual activity",
		Description:    "Sent when the server detects activity that looks anomalous.",
		DefaultSubject: "mint-ca: unusual activity detected",
		DefaultBody:    "Unusual activity was detected.\n\nActor: {{.actor}}\nDetails: {{.details}}\nTime: {{.timestamp}}\n",
	})
}
