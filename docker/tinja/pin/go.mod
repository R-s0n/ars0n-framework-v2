module github.com/Hackmanit/TInjA

go 1.26.0

// The go line above makes Go 1.26 the GODEBUG baseline. This block restores only the client TLS
// settings the previous image had (upstream go 1.23.0, built with go1.24.3),
// so the tool still reaches legacy-TLS targets instead of failing the handshake silently.
// Every other setting, including the net/url and net/http parsing limits, stays at the
// Go 1.26 default.
godebug (
	rsa1024min=0
	tlsmlkem=0
	tlssha1=1
)
