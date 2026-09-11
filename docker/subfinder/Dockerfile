# Pinned, not :latest. The framework parses subfinder's output and describes its flags from measured
# behaviour, so a floating tag makes the binary and the code that reads it drift apart silently.
# Verified: the installed image reports v2.16.0, so this pin changes nothing today.
FROM projectdiscovery/subfinder:v2.16.0

ENTRYPOINT ["subfinder"] 