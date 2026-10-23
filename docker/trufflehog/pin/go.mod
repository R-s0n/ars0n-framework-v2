module github.com/trufflesecurity/trufflehog/v3

go 1.26.0

replace github.com/jpillora/overseer => github.com/trufflesecurity/overseer v1.2.8

// Coinbase archived this library and it has some vulnerable dependencies so we've forked.
replace github.com/coinbase/waas-client-library-go => github.com/trufflesecurity/waas-client-library-go v1.0.9
