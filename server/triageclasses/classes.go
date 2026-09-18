// Package triageclasses is where the twenty-seven triage classifiers live.
//
// WHY IT IS A SEPARATE PACKAGE FROM triage, WHICH IS THE ENTIRE POINT. A classifier is the one
// piece of this system that must not be able to read another class's response. Everything else in
// the layer, the runner included, legitimately handles every class's responses at once. So the
// classifiers are put where the compiler can hold them to it: this package imports triage and
// NOTHING ELSE from the layer, and every field behind triage's vault is unexported, so the four
// oldest leaks are not refused at run time, they do not build.
//
//	(a) reading the observation field off a Perturbed        p.obs            undefined
//	(b) forging a Perturbed struct literal                   Perturbed{...}   unknown fields
//	(c) laundering a foreign response through NewReplay      p.Obs(p.Owner()) undefined
//	(d) ranging the vault's map, or reaching one by run id   p.vault.held     undefined
//
// leak_test.go builds each of those and asserts the build fails, with the compiler's exact words
// in the failure message.
//
// AND WHY IT SITS AT server/triageclasses AND NOT UNDER server/utils, WHICH IS THE SECOND POINT.
// A package split makes unexported mean something to the COMPILER and nothing at all to reflect.
// An adversarial audit ran fifteen attempts against the split version and five succeeded, three of
// them with no unsafe: reflect walks straight through an unexported field, so the one handle a
// classifier is legitimately given led, pointer by pointer, to a map holding every class's
// Observation. The fix is that the object at the end of that pointer is now one class's partition,
// so a reflect walk from a handle enumerates the caller's own responses and nothing else.
//
// The write side had to close with it, because a class that can MINT can name any owner and get a
// handle into that owner's partition. Minting, releasing and filtering now take a capability whose
// type lives in server/utils/internal/triagecap, and Go's internal rule is what makes that
// unreachable: a/b/internal/c is importable by everything under a/b, so this package has to sit
// OUTSIDE server/utils for the rule to bite. That is the whole reason for the directory's
// location, and moving it back under server/utils would silently reopen every write-side hole.
//
// IT MAY NOT IMPORT utils EITHER, and not only because that would be a cycle. utils holds the
// runner, the store and the marker allocator. A class is handed a marker in a ProbeRequest.
//
// THE CLAIM ABOUT THE MINTER IS NOW TRUE. This comment used to say a class could not reach the
// minter while triage.MintMarkerAt sat there exported and callable, and the audit called it from
// here on every attempt. It takes the capability now, so the sentence and the code agree.
//
// NO unsafe, NO reflect, NO go:linkname. importguard_test.go enumerates this directory and
// refuses all three. It is a test rather than a structure because Go has no way to forbid a
// linkname structurally, but it enumerates a CLOSED directory rather than matching a filename
// pattern, and it checks a property that cannot be spelled another way. The predecessor guard
// globbed "triage*.go" and a reviewer walked past it by naming the file sqliClassifier.go.
//
// HOW A CLASS GETS RUN. It registers itself from init() with triage.RegisterClassifier, package
// utils blank-imports this package, and the runner iterates triage.RegisteredClassifiers(). There
// is no switch statement anywhere and no list of classes to keep in sync: adding a class is adding
// a file to this directory.
package triageclasses
