module github.com/jaeles-project/gospider

go 1.26.0

// The go line above makes Go 1.26 the GODEBUG baseline. This block restores only the client TLS
// settings the previous image had (upstream go 1.16, built with go1.24),
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

require (
	github.com/gocolly/colly/v2 v2.1.0
	github.com/json-iterator/go v1.1.11
	github.com/mitchellh/go-homedir v1.1.0
	github.com/oxffaa/gopher-parse-sitemap v0.0.0-20191021113419-005d2eb1def4
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.1.3
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	golang.org/x/net v0.60.0
)

require (
	github.com/PuerkitoBio/goquery v1.5.1 // indirect
	github.com/andybalholm/cascadia v1.2.0 // indirect
	github.com/antchfx/htmlquery v1.2.3 // indirect
	github.com/antchfx/xmlquery v1.3.1 // indirect
	github.com/antchfx/xpath v1.3.9 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/kennygrant/sanitize v1.2.4 // indirect
	github.com/mattn/go-colorable v0.0.9 // indirect
	github.com/mattn/go-isatty v0.0.3 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/onsi/ginkgo v1.16.4 // indirect
	github.com/onsi/gomega v1.13.0 // indirect
	github.com/saintfish/chardet v0.0.0-20120816061221-3af4cd4741ca // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/temoto/robotstxt v1.1.1 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)
