package utils

import "ars0n-framework-v2-server/utils/internal/triagecap"

// The runner's side of the triage minting capability.
//
// WHAT THIS FILE IS FOR. Every entry point in package triage that MINTS a response, opens or
// releases a run's vault, filters a class's own set, or issues a marker or a run id takes a
// triagecap.Runner. The capability's type lives in server/utils/internal/triagecap, so Go's
// internal rule decides who can name it: everything under server/utils can, and nothing else can.
// This package is the runner, so it can, and this is the one place it says so.
//
// WHY IT IS A FUNCTION AND NOT A PACKAGE-LEVEL VARIABLE. A package-level var is a symbol, and a
// symbol is all //go:linkname needs. The capability is cheap to issue, so it is issued at the
// point of use and held by the object that needs it, and there is no process-lifetime name for
// anything to reach for.
//
// WHY IT IS UNEXPORTED. The classifiers cannot import this package at all, because it holds the
// runner and importing it would be a cycle, so exporting the helper would not hand them anything.
// It stays unexported anyway: the number of ways to obtain a capability is the number of things
// that have to be audited when somebody asks "who can mint", and that number should be one.
func triageRunnerCapability() triagecap.Runner { return triagecap.Grant() }
