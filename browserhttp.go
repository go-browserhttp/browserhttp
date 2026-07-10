// Package browserhttp builds a portable, pure-Go (CGO=0) http.Client that
// presents a real Chrome TLS fingerprint via uTLS. Many platforms (Reddit,
// Twitter, Instagram, TikTok) 403 non-browser clients based largely on the TLS
// ClientHello — Go's default handshake is trivially distinguishable from a
// browser's. Mimicking Chrome's ciphers/extensions/curves, plus a browser
// User-Agent and a warmed cookie jar, lets a plain Go client reach the public
// endpoints without any host web view. It works identically on macOS, Linux and
// Windows, and is shared by every provider that needs to look like a browser.
package browserhttp

import (
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DefaultUserAgent is a current desktop-Chrome User-Agent string. Providers set
// it (or their own) on outgoing requests; it is not applied automatically.
const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// NewClient returns an http.Client whose TLS handshakes impersonate Chrome and
// which keeps cookies across requests.
func NewClient(timeout time.Duration) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:   timeout,
		Jar:       jar,
		Transport: NewTransport(),
	}
}

// NewTransport returns an http.Transport that dials TLS with a Chrome
// fingerprint (forced to HTTP/1.1 so net/http drives the connection).
func NewTransport() *http.Transport {
	return &http.Transport{
		DialTLSContext:      dialChromeTLS,
		MaxIdleConns:        20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
}

// These operations are package vars so tests can inject a trusted root or force
// the otherwise-untriggerable uTLS error branches. Production keeps full
// certificate verification (no InsecureSkipVerify).
var (
	newTLSConfig = func(host string) *utls.Config { return &utls.Config{ServerName: host} }
	chromeSpec   = func() (utls.ClientHelloSpec, error) { return utls.UTLSIdToSpec(utls.HelloChrome_Auto) }
	applyPreset  = func(u *utls.UConn, spec *utls.ClientHelloSpec) error { return u.ApplyPreset(spec) }
	handshake    = func(ctx context.Context, u *utls.UConn) error { return u.HandshakeContext(ctx) }
)

// dialChromeTLS dials addr and completes a uTLS handshake presenting Chrome's
// ClientHello, with ALPN pinned to http/1.1.
func dialChromeTLS(ctx context.Context, network, addr string) (net.Conn, error) {
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

	uconn := utls.UClient(raw, newTLSConfig(host), utls.HelloCustom)
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
