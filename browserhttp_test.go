package browserhttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

func TestNewClientWithOptionsShape(t *testing.T) {
	c := NewClientWithOptions(3*time.Second, Options{InsecureSkipVerify: true})
	if c.Timeout != 3*time.Second {
		t.Fatalf("Timeout = %v", c.Timeout)
	}
	if c.Jar == nil {
		t.Fatal("nil cookie jar")
	}
	if _, ok := c.Transport.(*http.Transport); !ok {
		t.Fatalf("Transport type = %T", c.Transport)
	}
}

func TestClientRoundTripThroughTransport(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil)
	host := tlsServer(t, leaf)

	// Drive a real request so the transport's DialTLSContext closure runs.
	c := NewClientWithOptions(10*time.Second, Options{ExtraRootPEM: ca.pemDER})
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestNewTransportTuning(t *testing.T) {
	for _, tr := range []*http.Transport{NewTransport(), NewTransportWithOptions(Options{})} {
		if tr.MaxIdleConns != 20 || tr.IdleConnTimeout != 90*time.Second || tr.TLSHandshakeTimeout != 15*time.Second {
			t.Fatalf("transport tuning wrong: %+v", tr)
		}
		if tr.DialTLSContext == nil {
			t.Fatal("DialTLSContext not set")
		}
	}
}

func TestDefaultUserAgentIsBrowsery(t *testing.T) {
	if !strings.Contains(DefaultUserAgent, "Chrome/") || !strings.HasPrefix(DefaultUserAgent, "Mozilla/5.0") {
		t.Fatalf("UA does not look like a browser: %q", DefaultUserAgent)
	}
}

// --- test PKI helpers -------------------------------------------------------

type testCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	pemDER []byte // CA certificate in PEM form
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "browserhttp test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return &testCA{
		cert:   cert,
		key:    key,
		pemDER: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue mints a leaf certificate signed by the CA, valid for the given IPs and
// DNS names over the given validity window, and returns a tls.Certificate.
func (ca *testCA) issue(t *testing.T, notBefore, notAfter time.Time, ips []net.IP, dns []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "browserhttp test leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: nil}
}

// tlsServer starts an httptest TLS server presenting leaf and returns its
// host:port. The server verifies nothing about the client.
func tlsServer(t *testing.T, leaf tls.Certificate) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

// --- certificate verification behaviour ------------------------------------

func TestDialVerifiesValidChain(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil)
	host := tlsServer(t, leaf)

	conn, err := dialChromeTLS(context.Background(), "tcp", host, Options{ExtraRootPEM: ca.pemDER})
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	defer conn.Close()

	if tc, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		if proto := tc.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
			t.Fatalf("ALPN = %q, want http/1.1 (or empty)", proto)
		}
	}
}

func TestDialRejectsUntrustedRoot(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil)
	host := tlsServer(t, leaf)

	// No ExtraRootPEM: the CA is unknown to the OS/embedded trust store.
	if _, err := dialChromeTLS(context.Background(), "tcp", host, Options{}); err == nil {
		t.Fatal("want error for certificate signed by unknown authority")
	}
}

func TestDialRejectsWrongHost(t *testing.T) {
	ca := newTestCA(t)
	// Leaf is valid only for example.com, but we connect to 127.0.0.1.
	leaf := ca.issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		nil, []string{"example.com"})
	host := tlsServer(t, leaf)

	if _, err := dialChromeTLS(context.Background(), "tcp", host, Options{ExtraRootPEM: ca.pemDER}); err == nil {
		t.Fatal("want host-mismatch verification error")
	}
}

func TestDialRejectsExpiredCert(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issue(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil)
	host := tlsServer(t, leaf)

	if _, err := dialChromeTLS(context.Background(), "tcp", host, Options{ExtraRootPEM: ca.pemDER}); err == nil {
		t.Fatal("want expired-certificate verification error")
	}
}

func TestDialInsecureSkipVerifyAcceptsUntrusted(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil)
	host := tlsServer(t, leaf)

	// Untrusted CA, but verification is explicitly disabled.
	conn, err := dialChromeTLS(context.Background(), "tcp", host, Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("InsecureSkipVerify should accept untrusted cert: %v", err)
	}
	conn.Close()
}

// --- seam / error-branch coverage ------------------------------------------

func TestNewTLSConfigDefault(t *testing.T) {
	cfg := newTLSConfig("example.com", Options{})
	if cfg.ServerName != "example.com" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("default config must verify certificates")
	}
	if cfg.RootCAs == nil {
		t.Fatal("default config must carry a trust store")
	}
	cfg2 := newTLSConfig("h", Options{InsecureSkipVerify: true})
	if !cfg2.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify not threaded into config")
	}
}

func TestChromeSpecDefault(t *testing.T) {
	spec, err := chromeSpec()
	if err != nil {
		t.Fatalf("chromeSpec: %v", err)
	}
	if len(spec.CipherSuites) == 0 {
		t.Fatal("chromeSpec produced an empty ClientHello")
	}
}

func TestApplyPresetAndHandshakeDefaults(t *testing.T) {
	// Exercise the production applyPreset/handshake seam bodies via a real dial
	// to a trusted local server (default seams, no overrides).
	ca := newTestCA(t)
	leaf := ca.issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil)
	host := tlsServer(t, leaf)
	conn, err := dialChromeTLS(context.Background(), "tcp", host, Options{ExtraRootPEM: ca.pemDER})
	if err != nil {
		t.Fatalf("dial with default seams: %v", err)
	}
	conn.Close()
}

func TestDialChromeTLSSpecError(t *testing.T) {
	orig := chromeSpec
	chromeSpec = func() (utls.ClientHelloSpec, error) { return utls.ClientHelloSpec{}, errUnsupported }
	defer func() { chromeSpec = orig }()

	host := tlsServer(t, newTestCA(t).issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil))
	if _, err := dialChromeTLS(context.Background(), "tcp", host, Options{}); err == nil {
		t.Fatal("want error when chromeSpec fails")
	}
}

func TestDialChromeTLSApplyPresetError(t *testing.T) {
	orig := applyPreset
	applyPreset = func(_ *utls.UConn, _ *utls.ClientHelloSpec) error { return errUnsupported }
	defer func() { applyPreset = orig }()

	host := tlsServer(t, newTestCA(t).issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
		[]net.IP{net.ParseIP("127.0.0.1")}, nil))
	if _, err := dialChromeTLS(context.Background(), "tcp", host, Options{}); err == nil {
		t.Fatal("want error when ApplyPreset fails")
	}
}

// errUnsupported is a sentinel used to force seam error branches.
var errUnsupported = errorString("forced")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestDialChromeTLSDialError(t *testing.T) {
	// Port 1 on loopback is unlikely to accept; the dial fails before handshake.
	if _, err := dialChromeTLS(context.Background(), "tcp", "127.0.0.1:1", Options{}); err == nil {
		t.Fatal("expected dial error to closed port")
	}
}

func TestDialChromeTLSHostWithoutPort(t *testing.T) {
	// An addr with no port makes SplitHostPort fail; the code falls back to
	// using addr as the host and the dial then fails — covering that branch.
	if _, err := dialChromeTLS(context.Background(), "tcp", "nonexistent.invalid", Options{}); err == nil {
		t.Fatal("expected error dialing a portless bogus host")
	}
	var _ net.Error // ensure net import used
}

// --- trust-store loaders ----------------------------------------------------

func TestRootPoolAppendsExtra(t *testing.T) {
	ca := newTestCA(t)
	base := rootPool(nil)
	if base == nil {
		t.Fatal("base pool is nil")
	}
	with := rootPool(ca.pemDER)
	if with == nil {
		t.Fatal("extra pool is nil")
	}
	// Appending must not mutate the shared base pool.
	if len(with.Subjects()) <= len(base.Subjects()) {
		t.Fatalf("extra pool (%d) did not grow past base (%d)",
			len(with.Subjects()), len(base.Subjects()))
	}
}

func TestLoadBaseRootPoolSystemPopulated(t *testing.T) {
	ca := newTestCA(t)
	want := x509.NewCertPool()
	want.AddCert(ca.cert)

	origSys := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return want, nil }
	defer func() { systemCertPool = origSys }()

	got := loadBaseRootPool()
	if len(got.Subjects()) != 1 {
		t.Fatalf("expected system pool passthrough (1 subject), got %d", len(got.Subjects()))
	}
}

func TestLoadBaseRootPoolSystemEmptyFallsBack(t *testing.T) {
	origSys := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
	defer func() { systemCertPool = origSys }()

	got := loadBaseRootPool()
	if n := len(got.Subjects()); n == 0 {
		t.Fatal("empty system pool should fall back to a populated embedded bundle")
	}
}

func TestLoadBaseRootPoolSystemNilFallsBack(t *testing.T) {
	origSys := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, nil }
	defer func() { systemCertPool = origSys }()

	if n := len(loadBaseRootPool().Subjects()); n == 0 {
		t.Fatal("nil system pool should fall back to embedded bundle")
	}
}

func TestLoadBaseRootPoolSystemErrorFallsBack(t *testing.T) {
	origSys := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, errUnsupported }
	defer func() { systemCertPool = origSys }()

	if n := len(loadBaseRootPool().Subjects()); n == 0 {
		t.Fatal("system pool error should fall back to embedded bundle")
	}
}

func TestEmbeddedBundleIsUsableAndFresh(t *testing.T) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(embeddedRootsPEM())) {
		t.Fatal("embedded Mozilla bundle failed to parse as PEM")
	}
	if n := len(pool.Subjects()); n < 100 {
		t.Fatalf("embedded bundle has only %d roots; expected the full Mozilla list", n)
	}
}
