package main

// Copied into the TInjA source tree by docker/tinja/Dockerfile before `go build`; not part of upstream.
//
// rod (v0.116.2) does not look for an installed browser on its own: with no explicit binary,
// launcher.Launcher.getBin() calls Browser.Get(), which DOWNLOADS an unverified Chromium zip at scan
// time from whichever of several hosts answers first. ROD_BROWSER_BIN is not read by this rod version.
// Setting defaults.Bin here, after rod's own init has run, makes every launcher.New() use the distro
// chromium installed in the runtime stage, so --csti never fetches a browser.
import "github.com/go-rod/rod/lib/defaults"

func init() { defaults.Bin = "/usr/bin/chromium" }
