package browserhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestNewClientShape(t *testing.T) {
	c := NewClient(7 * time.Second)
	if c.Timeout != 7*time.Second {
		t.Fatalf("Timeout = %v", c.Timeout)
	}
	if c.Jar == nil {
		t.Fatal("nil cookie jar")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T", c.Transport)
	}
	if tr.DialTLSContext == nil {
		t.Fatal("DialTLSContext not set")
	}
}

func TestNewTransportTuning(t *testing.T) {
	tr := NewTransport()
	if tr.MaxIdleConns != 20 || tr.IdleConnTimeout != 90*time.Second || tr.TLSHandshakeTimeout != 15*time.Second {
		t.Fatalf("transport tuning wrong: %+v", tr)
	}
}

func TestDefaultUserAgentIsBrowsery(t *testing.T) {
	if !strings.Contains(DefaultUserAgent, "Chrome/") || !strings.HasPrefix(DefaultUserAgent, "Mozilla/5.0") {
		t.Fatalf("UA does not look like a browser: %q", DefaultUserAgent)
	}
}

// TestDialChromeTLSHandshake exercises the real uTLS handshake path against a
// local TLS server, keeping the test network-free (loopback only).
func TestDialChromeTLSHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Trust the test server's self-signed cert for this test only, keeping the
	// production verification path (no RootCAs override) intact.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	orig := newTLSConfig
	newTLSConfig = func(host string) *utls.Config {
		return &utls.Config{ServerName: host, RootCAs: pool}
	}
	defer func() { newTLSConfig = orig }()

	host := strings.TrimPrefix(srv.URL, "https://")
	conn, err := dialChromeTLS(context.Background(), "tcp", host)
	if err != nil {
		t.Fatalf("dialChromeTLS: %v", err)
	}
	defer conn.Close()

	// We negotiated the ALPN we pinned (http/1.1) over a verified handshake.
	if tc, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		if proto := tc.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
			t.Fatalf("ALPN = %q, want http/1.1 (or empty)", proto)
		}
	}
}

func TestDialChromeTLSHandshakeFailure(t *testing.T) {
	// No trusted-root override: the real handshake runs and fails to verify
	// httptest's self-signed cert, covering the handshake error branch.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := dialChromeTLS(context.Background(), "tcp", strings.TrimPrefix(srv.URL, "https://")); err == nil {
		t.Fatal("want handshake verification error against self-signed cert")
	}
}

func TestSeamDefaults(t *testing.T) {
	// Exercise the production default bodies directly.
	if cfg := newTLSConfig("example.com"); cfg.ServerName != "example.com" {
		t.Fatalf("newTLSConfig ServerName = %q", cfg.ServerName)
	}
	spec, err := chromeSpec()
	if err != nil {
		t.Fatalf("chromeSpec: %v", err)
	}
	if len(spec.CipherSuites) == 0 {
		t.Fatal("chromeSpec produced an empty ClientHello")
	}
}

func TestDialChromeTLSSpecError(t *testing.T) {
	orig := chromeSpec
	chromeSpec = func() (utls.ClientHelloSpec, error) {
		return utls.ClientHelloSpec{}, errUnsupported
	}
	defer func() { chromeSpec = orig }()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := dialChromeTLS(context.Background(), "tcp", strings.TrimPrefix(srv.URL, "https://")); err == nil {
		t.Fatal("want error when chromeSpec fails")
	}
}

func TestDialChromeTLSApplyPresetError(t *testing.T) {
	orig := applyPreset
	applyPreset = func(_ *utls.UConn, _ *utls.ClientHelloSpec) error { return errUnsupported }
	defer func() { applyPreset = orig }()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := dialChromeTLS(context.Background(), "tcp", strings.TrimPrefix(srv.URL, "https://")); err == nil {
		t.Fatal("want error when ApplyPreset fails")
	}
}

// errUnsupported is a sentinel used to force seam error branches.
var errUnsupported = errorString("forced")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestDialChromeTLSDialError(t *testing.T) {
	// Port 0 on an address the dialer cannot connect to yields a dial error
	// before any handshake.
	_, err := dialChromeTLS(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected dial error to closed port")
	}
}

func TestDialChromeTLSHostWithoutPort(t *testing.T) {
	// An addr with no port makes SplitHostPort fail; the code falls back to
	// using addr as the host and the dial then fails — covering that branch.
	_, err := dialChromeTLS(context.Background(), "tcp", "nonexistent.invalid")
	if err == nil {
		t.Fatal("expected error dialing a portless bogus host")
	}
	var _ net.Error // ensure net import used
}
