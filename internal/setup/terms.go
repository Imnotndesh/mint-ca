package setup

import (
	"fmt"
	"net/url"
)

// DefaultTermsText is mint-ca's Terms of Service. It follows the shape of
// terms published by commercial CAs and SSH/ACME onboarding tools (e.g.
// smallstep/step-ca): it scopes what the service provides, disclaims
// over-broad warranties, and limits liability to reduce the operator's
// exposure. Operators can replace this by serving their own terms document
// and pointing MINT_ACME_CAA/TOS config at it.
const DefaultTermsText = `MINT-CA TERMS OF SERVICE

By using this certificate authority, you agree to these terms.

1. PURPOSE
The certificate authority ("mint-ca", "the service") issues and manages
X.509 and SSH certificates used to secure network communications.

2. YOUR RESPONSIBILITIES
You are solely responsible for:
  - protecting the private keys associated with certificates you receive,
  - correctly configuring and deploying certificates you obtain,
  - ensuring you have the lawful right to request certificates for the
    domains, hosts and subjects you enrol, and
  - promptly revoking any certificate that is compromised or no longer
    authorised.

3. NO WARRANTY
The service is provided "as is" and "as available", without warranties of
any kind, whether express or implied, including but not limited to implied
warranties of merchantability, fitness for a particular purpose and
non-infringement.

4. LIMITATION OF LIABILITY
To the maximum extent permitted by law, the operator(s) of mint-ca shall
not be liable for any indirect, incidental, special, consequential or
punitive damages, or any loss of profits, revenue, data or goodwill, arising
from or relating to your use of, or inability to use, the service.

5. NO GUARANTEE OF AVAILABILITY
The service may be suspended, discontinued or amended at any time, with or
without notice.

6. CHANGES TO THESE TERMS
These terms may be updated from time to time. Continued use of the service
after a change constitutes acceptance of the revised terms.

By agreeing, you confirm you have read, understood and accepted these terms.
`

// TermsPath is the public endpoint at which the terms of service text is
// served, so both the ACME directory and the setup flow can reference it.
const TermsPath = "/pki/terms"

// DefaultTermsURL builds the absolute terms-of-service URL for a given base
// URL (e.g. "https://ca.example.com"). base may already include a scheme and
// host; TermsPath is appended.
func DefaultTermsURL(base string) string {
	return fmt.Sprintf("%s%s", base, TermsPath)
}

// TermsURL returns the terms URL to advertise, or "" if not configured.
func TermsURL(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return DefaultTermsURL(base)
}
