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

require (
	github.com/fatih/color v1.18.0
	github.com/go-rod/rod v0.116.2
	github.com/spf13/cobra v1.9.1
	github.com/spf13/pflag v1.0.6
	github.com/spf13/viper v1.20.1
	golang.org/x/net v0.60.0
)

require moul.io/http2curl v1.0.0

require (
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/smartystreets/goconvey v1.8.1 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

require (
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.8.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/ysmood/fetchup v0.3.0 // indirect
	github.com/ysmood/goob v0.4.0 // indirect
	github.com/ysmood/got v0.40.0 // indirect
	github.com/ysmood/gson v0.7.3 // indirect
	github.com/ysmood/leakless v0.9.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.11.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
