module github.com/Hackmanit/Web-Cache-Vulnerability-Scanner

go 1.26.0

// The go line above makes Go 1.26 the GODEBUG baseline. This block restores only the client TLS
// settings the previous image had (upstream go 1.23.0, built with go1.23),
// so the tool still reaches legacy-TLS targets instead of failing the handshake silently.
// Every other setting, including the net/url and net/http parsing limits, stays at the
// Go 1.26 default.
godebug (
	rsa1024min=0
	tlssha1=1
)

require (
	github.com/fatih/color v1.18.0
	github.com/xplorfin/fasthttp2curl v0.28.0
	golang.org/x/net v0.60.0
	golang.org/x/time v0.12.0
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
)

require (
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/valyala/fasthttp v1.70.0
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
