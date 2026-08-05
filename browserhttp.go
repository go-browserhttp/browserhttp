// Package browserhttp builds a portable, pure-Go (CGO=0) http.Client that
// presents a real Chrome TLS fingerprint via uTLS. Many platforms (Reddit,
// Twitter, Instagram, TikTok) 403 non-browser clients based largely on the TLS
// ClientHello — Go's default handshake is trivially distinguishable from a
// browser's. Mimicking Chrome's ciphers/extensions/curves, plus a browser
// User-Agent and a warmed cookie jar, lets a plain Go client reach the public
// endpoints without any host web view. It works identically on macOS, Linux and
// Windows, and is shared by every provider that needs to look like a browser.
//
// # Certificate verification
//
// The client performs real X.509 chain and host-name verification on every
// HTTPS handshake; it never uses InsecureSkipVerify in the default path. The
// trust store is resolved once per process:
//
//   - The OS system pool (crypto/x509.SystemCertPool) is used when it is
//     populated — this covers Linux (/etc/ssl/...) and Windows (the syscall
//     cert store).
//   - Otherwise the client falls back to an embedded copy of the Mozilla
//     Included CA Certificate List. This is essential under CGO=0 on macOS,
//     where SystemCertPool is always empty (Go defers to the platform verifier,
//     which a cgo-free binary cannot reach), and for FROM-scratch containers
//     that ship no OS trust store at all.
//
// Callers can append private-CA / test roots (Options.ExtraRootPEM) and, as an
// explicit and clearly-named opt-in, disable verification entirely
// (Options.InsecureSkipVerify) — but the default always verifies.
package browserhttp

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/breml/rootcerts/embedded"
	utls "github.com/refraction-networking/utls"
)

// DefaultUserAgent is a current desktop-Chrome User-Agent string. Providers set
// it (or their own) on outgoing requests; it is not applied automatically.
const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// Options tunes the TLS trust behaviour of a client or transport. The zero
// value is safe: it verifies certificates against the OS/embedded trust store
// and skips nothing.
type Options struct {
	// ExtraRootPEM, when non-empty, is a PEM bundle of additional trusted root
	// certificates appended to the trust store. Use it for private CAs or to
	// trust a test server's self-signed certificate. It augments — never
	// replaces — the OS/embedded roots.
	ExtraRootPEM []byte

	// InsecureSkipVerify disables all certificate chain and host-name
	// verification. It is off by default and MUST stay off outside of
	// deliberate, well-understood cases (e.g. probing a host whose self-signed
	// certificate cannot be supplied as an extra root). The name mirrors
	// crypto/tls so the risk is unmistakable at the call site.
	InsecureSkipVerify bool
}

// NewClient returns an http.Client whose TLS handshakes impersonate Chrome,
// which verifies server certificates against the OS/embedded trust store, and
// which keeps cookies across requests.
func NewClient(timeout time.Duration) *http.Client {
	return NewClientWithOptions(timeout, Options{})
}

// NewClientWithOptions is NewClient with explicit TLS trust Options.
func NewClientWithOptions(timeout time.Duration, opts Options) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:   timeout,
		Jar:       jar,
		Transport: NewTransportWithOptions(opts),
	}
}

// NewTransport returns an http.Transport that dials TLS with a Chrome
// fingerprint (forced to HTTP/1.1 so net/http drives the connection) and full
// certificate verification.
func NewTransport() *http.Transport {
	return NewTransportWithOptions(Options{})
}

// NewTransportWithOptions is NewTransport with explicit TLS trust Options.
func NewTransportWithOptions(opts Options) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialChromeTLS(ctx, network, addr, opts)
		},
		MaxIdleConns:        20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
}

// These operations are package vars so tests can inject roots or force the
// otherwise-untriggerable uTLS error branches. Production keeps full
// certificate verification (no InsecureSkipVerify).
var (
	newTLSConfig = func(host string, opts Options) *utls.Config {
		return &utls.Config{
			ServerName:         host,
			RootCAs:            rootPool(opts.ExtraRootPEM),
			InsecureSkipVerify: opts.InsecureSkipVerify,
		}
	}
	chromeSpec  = func() (utls.ClientHelloSpec, error) { return utls.UTLSIdToSpec(utls.HelloChrome_Auto) }
	applyPreset = func(u *utls.UConn, spec *utls.ClientHelloSpec) error { return u.ApplyPreset(spec) }
	handshake   = func(ctx context.Context, u *utls.UConn) error { return u.HandshakeContext(ctx) }
)

// dialChromeTLS dials addr and completes a uTLS handshake presenting Chrome's
// ClientHello, with ALPN pinned to http/1.1.
func dialChromeTLS(ctx context.Context, network, addr string, opts Options) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Start from Chrome's fingerprint, then pin ALPN to http/1.1 so net/http
	// (which speaks HTTP/1.1 over this conn) and the negotiated protocol agree.
	spec, err := chromeSpec()
	if err != nil {
		raw.Close()
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}

	uconn := utls.UClient(raw, newTLSConfig(host, opts), utls.HelloCustom)
	if err := applyPreset(uconn, &spec); err != nil {
		raw.Close()
		return nil, err
	}
	if err := handshake(ctx, uconn); err != nil {
		raw.Close()
		return nil, err
	}
	return uconn, nil
}

// Trust-store seams. Overridable in tests to drive both the OS-pool and
// embedded-fallback branches deterministically.
var (
	systemCertPool   = x509.SystemCertPool
	embeddedRootsPEM = embedded.MozillaCACertificatesPEM
)

// baseRootPool holds the process-wide trust store (OS pool or embedded
// fallback), parsed at most once.
var (
	baseRootOnce sync.Once
	baseRootPool *x509.CertPool
)

// rootPool returns the trust store used to verify server certificates. It
// starts from the cached base pool (OS system roots when populated, otherwise
// the embedded Mozilla bundle) and, when extraPEM is non-empty, returns a clone
// with those extra roots appended so the shared base pool is never mutated.
func rootPool(extraPEM []byte) *x509.CertPool {
	baseRootOnce.Do(func() { baseRootPool = loadBaseRootPool() })
	if len(extraPEM) == 0 {
		return baseRootPool
	}
	pool := baseRootPool.Clone()
	pool.AppendCertsFromPEM(extraPEM)
	return pool
}

// loadBaseRootPool resolves the base trust store: the OS system pool when it is
// available and non-empty, otherwise the embedded Mozilla CA bundle. macOS
// (SystemCertPool is always empty there under Go) and FROM-scratch containers
// take the embedded path.
func loadBaseRootPool() *x509.CertPool {
	if p, err := systemCertPool(); err == nil && p != nil && len(p.Subjects()) > 0 {
		return p
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(embeddedRootsPEM()))
	return pool
}
