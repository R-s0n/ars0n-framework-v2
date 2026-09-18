// Package triageadversary holds the runtime half of the isolation law's regression suite.
//
// WHY IT EXISTS AS ITS OWN PACKAGE. The compile-fail fixtures in the classifier package prove that
// certain expressions do not build. They are structurally blind to an attack that DOES build, and
// five of the fifteen attacks an adversarial audit ran against this layer compiled cleanly, passed
// go vet, and returned other classes' response bodies byte for byte. A compile-fail harness cannot
// see those, so they live here instead, as ordinary tests that run the attack and assert it comes
// back with nothing.
//
// WHAT EACH TEST IS ALLOWED TO USE. The setup half mints responses for several classes into one
// run, which is the runner's job and needs the runner's capability. The ATTACK half takes nothing
// but a triage.ClassifyCtx and uses nothing but what a classifier can reach: the exported triage
// API, reflect, and unsafe. Every attack function in this package has the signature
//
//	func(triage.ClassifyCtx) map[triage.ClassID]string
//
// so the code cannot quietly help itself to the surrounding package's minting rights. It returns
// what it managed to read, keyed by the class the body belonged to, and the test asserts that the
// only key is the ctx's own class.
package triageadversary
