package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type TestResult string

const (
	Supported   TestResult = "supported"
	Unsupported TestResult = "unsupported"
	NotTestable TestResult = "not_testable"
	Error       TestResult = "error"
)

type Observation struct {
	Host              string
	Port              int
	SupportedVersions map[uint16]TestResult
	CipherSuites      map[uint16]TestResult
	NegotiatedALPN    string
	Chain             []*x509.Certificate
	OCSPStapled       bool
	SCTCount          int
	HandshakeMillis   int64
	Errors            []string
}

type Options struct {
	Timeout time.Duration
}

func Probe(ctx context.Context, host string, port int, opts Options) (*Observation, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	obs := &Observation{
		Host:              host,
		Port:              port,
		SupportedVersions: make(map[uint16]TestResult),
		CipherSuites:      make(map[uint16]TestResult),
		Errors:            []string{},
	}

	target := fmt.Sprintf("%s:%d", host, port)

	// Probe TLS 1.2
	cfg12 := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}
	chain, err := doHandshake(ctx, target, cfg12, opts.Timeout, obs)
	if err == nil && len(chain) > 0 {
		obs.Chain = chain
	}

	// Probe TLS 1.3
	cfg13 := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	chain13, err := doHandshake(ctx, target, cfg13, opts.Timeout, obs)
	if err == nil && len(chain13) > 0 && len(obs.Chain) == 0 {
		obs.Chain = chain13
	}

	// For older versions, Go doesn't support them well or at all, mark NotTestable
	obs.SupportedVersions[tls.VersionTLS10] = NotTestable
	obs.SupportedVersions[tls.VersionTLS11] = NotTestable

	return obs, nil
}

func doHandshake(ctx context.Context, target string, cfg *tls.Config, timeout time.Duration, obs *Observation) ([]*x509.Certificate, error) {
	start := time.Now()
	
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, cfg)
	if err != nil {
		obs.SupportedVersions[cfg.MaxVersion] = Unsupported
		obs.Errors = append(obs.Errors, fmt.Sprintf("TLS 0x%04x: %v", cfg.MaxVersion, err))
		return nil, err
	}
	defer conn.Close()

	obs.HandshakeMillis = time.Since(start).Milliseconds()
	
	state := conn.ConnectionState()
	obs.SupportedVersions[state.Version] = Supported
	obs.CipherSuites[state.CipherSuite] = Supported
	obs.NegotiatedALPN = state.NegotiatedProtocol

	if len(state.PeerCertificates) > 0 {
		if len(state.OCSPResponse) > 0 {
			obs.OCSPStapled = true
		}
		obs.SCTCount = len(state.SignedCertificateTimestamps)
		return state.PeerCertificates, nil
	}
	return nil, nil
}
