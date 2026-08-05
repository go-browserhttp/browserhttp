<p align="center"><img src="https://raw.githubusercontent.com/go-browserhttp/brand/main/social/go-browserhttp.png" alt="go-browserhttp/browserhttp" width="720"></p>

# go-browserhttp / browserhttp

[![CI](https://github.com/go-browserhttp/browserhttp/actions/workflows/ci.yml/badge.svg)](https://github.com/go-browserhttp/browserhttp/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-browserhttp/browserhttp.svg)](https://pkg.go.dev/github.com/go-browserhttp/browserhttp)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

A pure-Go (**CGO=0**) `http.Client` that presents a real **Chrome TLS
fingerprint** via [uTLS](https://github.com/refraction-networking/utls). Many
sites 403 non-browser clients based largely on the TLS ClientHello; mimicking
Chrome's ciphers/extensions/curves — plus a browser User-Agent and a warmed
cookie jar — lets a plain Go client reach public endpoints with **no host web
view**. Identical on macOS, Linux and Windows.

```go
c := browserhttp.NewClient(30 * time.Second)
resp, err := c.Get("https://www.reddit.com/r/golang/hot.json")
```

Extracted from `go-news-reader/reader`; shared by any fetcher that must look
like a browser.

## Certificate verification

The client performs **real X.509 chain and host-name verification** on every
HTTPS handshake — it never uses `InsecureSkipVerify` in the default path. The
trust store is resolved once per process:

- The **OS system pool** (`crypto/x509.SystemCertPool`) is used when it is
  populated — this covers Linux (`/etc/ssl/...`) and Windows (the syscall cert
  store).
- Otherwise the client falls back to an **embedded Mozilla CA bundle** (the
  "Mozilla Included CA Certificate List" from the Common CA Database, via
  [`github.com/breml/rootcerts/embedded`](https://github.com/breml/rootcerts),
  MPL-2.0). This is essential under **CGO=0 on macOS**, where `SystemCertPool`
  is always empty because Go defers to a platform verifier a cgo-free binary
  cannot reach, and for **`FROM scratch`** containers that ship no OS trust
  store at all.

Two knobs are available via `Options`, threaded through `NewClientWithOptions`
and `NewTransportWithOptions`:

```go
// Trust a private CA / test server, on top of the OS+embedded roots.
c := browserhttp.NewClientWithOptions(30*time.Second, browserhttp.Options{
    ExtraRootPEM: myCAPEM,
})

// Explicit, clearly-named opt-out (off by default — use only when you must).
c := browserhttp.NewClientWithOptions(30*time.Second, browserhttp.Options{
    InsecureSkipVerify: true,
})
```

## License

BSD-3-Clause © the go-browserhttp/browserhttp authors.
