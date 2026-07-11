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

## License

BSD-3-Clause © the go-browserhttp/browserhttp authors.
