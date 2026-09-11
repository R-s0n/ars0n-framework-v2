# Pinned, not :latest. companyRegistry.go states outright that "dnsx v1.2.2 HAS NO TIMEOUT FLAG OF
# ANY KIND", which is a claim about one specific binary; a floating tag would let a release that adds
# one arrive without the registry knowing. Verified: the installed image reports 1.2.2, so this pin
# is a no-op today.
FROM projectdiscovery/dnsx:v1.2.2

ENTRYPOINT ["dnsx"] 