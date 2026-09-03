package utils

import "strings"

// Reducing a hostname to the domain somebody can actually register.
//
// WHY THIS FILE EXISTS. shodan_company's extractRootDomain splits on dots and keeps the last two
// labels, ALWAYS. Measured by running the verbatim function: www.acme.co.uk becomes "co.uk",
// api.acme.com.au becomes "com.au", mail.acme.co.jp becomes "co.jp", host.acme.gov.uk becomes
// "gov.uk", acme.co.za becomes "co.za" and acme.s3.amazonaws.com becomes "amazonaws.com". Every one
// of those is then merged into the consolidated root-domain list, which the UI offers to promote into
// a Wildcard scope target - so promoting "co.uk" starts a subdomain enumeration against the whole of
// the United Kingdom's commercial namespace. That is the scope escape the vocabulary calls out, and
// three separate options (shodan publicSuffixAwareRootDomain, censys reduceToRegistrableDomain,
// github_recon reduceToRegistrableDomain) all depend on getting this right.
//
// WHAT THIS IS AND, MORE IMPORTANTLY, WHAT IT IS NOT.
//
// It is NOT the Mozilla Public Suffix List. The server module depends on uuid, mux and pgx and
// nothing else; golang.org/x/net/publicsuffix is not vendored and adding a dependency is not a
// runner change. So this is a CURATED TABLE of the multi-label suffixes that were actually measured
// producing a wrong answer, plus the country-code second-level patterns that produce the same class
// of wrong answer, and it is deliberately CONSERVATIVE: when it does not recognise a suffix it falls
// back to the last two labels, which is exactly today's behaviour, so it can never be worse than the
// function it replaces.
//
// THE HONEST LIMITATION, WHICH MUST NOT BE LOST: a real PSL has thousands of entries and is updated
// weekly. This table covers the common cases and the measured ones. A hostname under an unusual
// multi-label suffix will still reduce to that suffix, so the consolidation step still needs a
// rejection guard of its own before anything here is treated as a complete fix.

// companyKnownMultiLabelSuffixes is the set of suffixes under which the REGISTRABLE name is the
// label to their left, so a two-label reduction is wrong by exactly one label.
//
// Three groups, and the reason for each is different:
//
//   - the ccTLD second levels (co.uk, com.au, ...), where the two-label answer is a public suffix;
//   - the measured cloud and CDN suffixes (s3.amazonaws.com, ...), where the two-label answer is a
//     third party's domain that the operator will then treat as a company asset;
//   - the platform suffixes (github.io, herokuapp.com, ...), where every customer shares one
//     two-label domain.
var companyKnownMultiLabelSuffixes = map[string]bool{
	// ccTLD second-level registries. The measured failures were co.uk, com.au, co.jp, gov.uk and co.za.
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "net.uk": true, "sch.uk": true,
	"me.uk": true, "ltd.uk": true, "plc.uk": true, "police.uk": true, "nhs.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true, "ac.nz": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true, "lg.jp": true,
	"co.kr": true, "or.kr": true, "ne.kr": true, "go.kr": true, "re.kr": true,
	"co.za": true, "org.za": true, "net.za": true, "gov.za": true, "ac.za": true, "web.za": true,
	"co.in": true, "net.in": true, "org.in": true, "gov.in": true, "ac.in": true, "edu.in": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true, "edu.br": true,
	"com.mx": true, "org.mx": true, "gob.mx": true, "edu.mx": true,
	"com.ar": true, "net.ar": true, "org.ar": true, "gob.ar": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true, "ac.cn": true,
	"com.hk": true, "net.hk": true, "org.hk": true, "gov.hk": true, "edu.hk": true,
	"com.sg": true, "net.sg": true, "org.sg": true, "gov.sg": true, "edu.sg": true,
	"com.tw": true, "net.tw": true, "org.tw": true, "gov.tw": true, "edu.tw": true,
	"com.tr": true, "net.tr": true, "org.tr": true, "gov.tr": true, "edu.tr": true,
	"com.pl": true, "net.pl": true, "org.pl": true, "gov.pl": true,
	"com.ru": true, "net.ru": true, "org.ru": true, "gov.ru": true,
	"com.ua": true, "net.ua": true, "org.ua": true, "gov.ua": true,
	"co.il": true, "net.il": true, "org.il": true, "gov.il": true, "ac.il": true,
	"com.my": true, "net.my": true, "org.my": true, "gov.my": true, "edu.my": true,
	"com.ph": true, "net.ph": true, "org.ph": true, "gov.ph": true,
	"co.th": true, "in.th": true, "go.th": true, "ac.th": true,
	"com.vn": true, "net.vn": true, "org.vn": true, "gov.vn": true, "edu.vn": true,
	"com.co": true, "net.co": true, "gov.co": true, "edu.co": true,
	"co.id": true, "or.id": true, "go.id": true, "ac.id": true, "web.id": true,
	"com.pk": true, "net.pk": true, "org.pk": true, "gov.pk": true,
	"com.eg": true, "net.eg": true, "org.eg": true, "gov.eg": true,
	"com.sa": true, "net.sa": true, "org.sa": true, "gov.sa": true, "edu.sa": true,
	"com.ng": true, "net.ng": true, "org.ng": true, "gov.ng": true,
	"co.ke": true, "or.ke": true, "go.ke": true, "ac.ke": true,
	"com.es": true, "org.es": true, "gob.es": true, "edu.es": true,
	"co.at": true, "or.at": true, "ac.at": true, "gv.at": true,
	"com.pt": true, "org.pt": true, "gov.pt": true, "edu.pt": true,
	"com.gr": true, "net.gr": true, "org.gr": true, "gov.gr": true, "edu.gr": true,

	// MEASURED. acme.s3.amazonaws.com reducing to "amazonaws.com" is the case that was reproduced by
	// running shodan_company's function verbatim.
	"s3.amazonaws.com": true, "s3-website.amazonaws.com": true,
	"compute.amazonaws.com": true, "compute-1.amazonaws.com": true,
	"elb.amazonaws.com": true, "execute-api.amazonaws.com": true,
	"blob.core.windows.net": true, "queue.core.windows.net": true, "table.core.windows.net": true,
	"file.core.windows.net": true, "web.core.windows.net": true,
	"cloudapp.azure.com": true, "storage.googleapis.com": true, "appspot.com": true,

	// Multi-tenant platform suffixes: one two-label domain shared by every customer, so reducing to it
	// stores a third party as a company root domain.
	"github.io": true, "gitlab.io": true, "herokuapp.com": true, "herokudns.com": true,
	"netlify.app": true, "vercel.app": true, "pages.dev": true, "workers.dev": true,
	"cloudfront.net": true, "azurewebsites.net": true, "azureedge.net": true,
	"akamaized.net": true, "akamaihd.net": true, "fastly.net": true, "cdn77.org": true,
	"amazonaws.com.cn": true, "elasticbeanstalk.com": true, "firebaseapp.com": true,
	"web.app": true, "myshopify.com": true, "wpengine.com": true, "readthedocs.io": true,
	"zendesk.com": true, "freshdesk.com": true, "statuspage.io": true, "surge.sh": true,
	"trafficmanager.net": true, "digitaloceanspaces.com": true, "r2.dev": true,
}

// companyRegistrableDomain returns the registrable domain of a hostname, or "" when the input is not
// a hostname at all.
//
// The rule: walk the known multi-label suffixes longest first, and if one matches, keep ONE more
// label than it. Otherwise fall back to the last two labels, which is what the code did before and
// therefore cannot be a regression.
//
// Case is normalised and a trailing dot and a leading "*." wildcard are stripped, because a
// certificate SAN routinely carries both and neither is a different domain.
func companyRegistrableDomain(hostname string) string {
	host := strings.ToLower(strings.TrimSpace(hostname))
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "*.")
	if host == "" || !strings.Contains(host, ".") {
		return ""
	}

	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}

	// Longest suffix first, so com.au wins over au and s3.amazonaws.com wins over amazonaws.com.
	// take == len(labels) is included deliberately: a hostname that IS a public suffix has no
	// registrable name at all, and returning the suffix is precisely the scope escape this function
	// exists to stop, so it returns "" and the caller drops it.
	for take := len(labels); take >= 2; take-- {
		suffix := strings.Join(labels[len(labels)-take:], ".")
		if !companyKnownMultiLabelSuffixes[suffix] {
			continue
		}
		if len(labels) == take {
			return ""
		}
		return strings.Join(labels[len(labels)-take-1:], ".")
	}

	// Not a suffix we know: the historical two-label answer, so this can never be worse than the
	// function it replaces.
	return strings.Join(labels[len(labels)-2:], ".")
}

// companyHasSuffix reports whether a hostname sits under one of the given domain suffixes.
//
// Label aware on purpose: "notacme.com" must not match the suffix "acme.com", and a bare
// strings.HasSuffix would say it does. That mistake in an EXCLUSION list silently deletes real
// findings, and in an INCLUSION list silently keeps somebody else's.
func companyHasSuffix(hostname string, suffixes []string) bool {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	for _, raw := range suffixes {
		suffix := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), ".")))
		suffix = strings.TrimSuffix(suffix, ".")
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
