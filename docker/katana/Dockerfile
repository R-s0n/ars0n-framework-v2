# Pinned, not :latest. companyOptionsKatana.go is written against THIS version: it records that -mdp
# is "new in v1.7.0" and carries measured output line counts (1 vs 10928, 10928 vs 22878) used to
# describe what each option does. A floating tag lets the next upstream release silently replace the
# binary those measurements describe, and katana is actively published, so that is a when not an if.
# Verified: the image currently installed reports v1.7.0, so this pin is a no-op today.
# Re-measure the option metadata before moving it.
FROM projectdiscovery/katana:v1.7.0

WORKDIR /app

ENTRYPOINT ["katana"] 