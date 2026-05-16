// Package checks implements the small allow-list of scans the
// probe is permitted to run. Posture / surface / misconfig only:
// no credentialed scans, no exploit attempts, no endpoint agent.
package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/postvaleapp/postvale-cli/internal/probe"
)

// Expiry-warning thresholds. Mirror the cloud-side TLS check so an
// internal asset gets graded against the same lens the customer
// already sees on public surfaces.
const (
	expiryWarnDays = 30
	expiryHighDays = 7
)

// TLS runs a single TLS-handshake check against host:port and emits
// one or more findings if the cert is misconfigured, weak, or about
// to expire. Caller picks the port from the work item; default 443.
func TLS(ctx context.Context, target string, port int) ([]probe.Finding, error) {
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort(target, fmt.Sprint(port))

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	cfg := &tls.Config{
		ServerName: target,
		// MinVersion left at default; we explicitly report what the
		// server negotiates and let the operator decide. The probe
		// reads, doesn't enforce.
		InsecureSkipVerify: false, //nolint:gosec
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		// Couldn't complete the handshake. Surface as bad-chain so
		// the dashboard renders the failure with the underlying
		// network or trust-store reason.
		return []probe.Finding{
			{
				Target:               target,
				Kind:                 "tls.bad-chain",
				Severity:             "high",
				Title:                fmt.Sprintf("TLS handshake failed: %s", err.Error()),
				Detail:               map[string]interface{}{"reason": err.Error(), "port": port},
				DistinguishingDetail: fmt.Sprintf("%s|%d|handshake-fail", target, port),
			},
		}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	leaf := state.PeerCertificates[0]
	now := time.Now()
	out := []probe.Finding{}

	// Expiry. Two thresholds because 'expires in 30 days' is medium
	// (plan the renewal) and 'expires in 7 days' is high (do it now).
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
	switch {
	case now.After(leaf.NotAfter):
		out = append(out, probe.Finding{
			Target:   target,
			Kind:     "tls.expired",
			Severity: "critical",
			Title: fmt.Sprintf(
				"TLS cert expired %d days ago",
				int(now.Sub(leaf.NotAfter).Hours()/24),
			),
			Detail: map[string]interface{}{
				"notAfter":  leaf.NotAfter.Format(time.RFC3339),
				"subject":   leaf.Subject.CommonName,
				"issuer":    leaf.Issuer.CommonName,
				"port":      port,
				"daysAfter": int(now.Sub(leaf.NotAfter).Hours() / 24),
			},
			DistinguishingDetail: fmt.Sprintf("%s|%d|expired", target, port),
		})
	case daysLeft <= expiryHighDays:
		out = append(out, probe.Finding{
			Target:               target,
			Kind:                 "tls.expiring",
			Severity:             "high",
			Title:                fmt.Sprintf("TLS cert expires in %d days", daysLeft),
			Detail:               expiryDetail(leaf, port, daysLeft),
			DistinguishingDetail: fmt.Sprintf("%s|%d|expiring-high", target, port),
		})
	case daysLeft <= expiryWarnDays:
		out = append(out, probe.Finding{
			Target:               target,
			Kind:                 "tls.expiring",
			Severity:             "medium",
			Title:                fmt.Sprintf("TLS cert expires in %d days", daysLeft),
			Detail:               expiryDetail(leaf, port, daysLeft),
			DistinguishingDetail: fmt.Sprintf("%s|%d|expiring-med", target, port),
		})
	}

	// Protocol version. TLS < 1.2 is the long-standing 'turn it off'
	// line; 1.2 is OK, 1.3 is preferred.
	if state.Version < tls.VersionTLS12 {
		out = append(out, probe.Finding{
			Target:   target,
			Kind:     "tls.weak-protocol",
			Severity: "high",
			Title:    fmt.Sprintf("TLS server negotiated %s (deprecated)", tlsVersionName(state.Version)),
			Detail: map[string]interface{}{
				"negotiatedVersion": tlsVersionName(state.Version),
				"port":              port,
			},
			DistinguishingDetail: fmt.Sprintf("%s|%d|proto-%s", target, port, tlsVersionName(state.Version)),
		})
	}

	// Chain verification. The handshake succeeded with the system
	// trust store, but explicitly verify against the host's SNI so
	// hostname-mismatch findings surface cleanly.
	verifyOpts := x509.VerifyOptions{
		DNSName:       target,
		Intermediates: x509.NewCertPool(),
	}
	for _, c := range state.PeerCertificates[1:] {
		verifyOpts.Intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(verifyOpts); err != nil {
		out = append(out, probe.Finding{
			Target:               target,
			Kind:                 "tls.bad-chain",
			Severity:             "high",
			Title:                fmt.Sprintf("TLS chain failed verification: %s", err.Error()),
			Detail:               map[string]interface{}{"reason": err.Error(), "port": port},
			DistinguishingDetail: fmt.Sprintf("%s|%d|chain-fail", target, port),
		})
	}

	return out, nil
}

func expiryDetail(leaf *x509.Certificate, port, daysLeft int) map[string]interface{} {
	return map[string]interface{}{
		"notAfter":    leaf.NotAfter.Format(time.RFC3339),
		"subject":     leaf.Subject.CommonName,
		"issuer":      leaf.Issuer.CommonName,
		"daysLeft":    daysLeft,
		"port":        port,
		"sanDNSNames": strings.Join(leaf.DNSNames, ","),
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
