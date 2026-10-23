module ars0n.local/build/ffuf

go 1.26.0

// The go line above makes Go 1.26 the GODEBUG baseline. This block restores only the client TLS
// settings the previous image had (upstream go 1.20, built with go1.24),
// so the tool still reaches legacy-TLS targets instead of failing the handshake silently.
// Every other setting, including the net/url and net/http parsing limits, stays at the
// Go 1.26 default.
godebug (
	rsa1024min=0
	tls3des=1
	tlsmlkem=0
	tlsrsakex=1
	tlssha1=1
	x509negativeserial=1
)

tool github.com/ffuf/ffuf/v2

require (
	github.com/PuerkitoBio/goquery v1.8.0 // indirect
	github.com/adrg/xdg v0.4.0 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/ffuf/ffuf/v2 v2.3.0 // indirect
	github.com/ffuf/pencode v0.0.0-20230421231718-2cea7e60a693 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
