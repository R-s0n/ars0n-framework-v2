// Package triagecap is the minting capability for the triage layer, and its whole job is to be
// UNREACHABLE from a classifier.
//
// THE PROBLEM IT SOLVES. Partitioning the response vault by (run, class) means the object graph a
// classifier can reach holds only that class's own responses, so a reflect walk from a handle
// enumerates nothing foreign. That is only half the answer. If a class can still MINT, it mints
// into whichever partition it names, and the handle it gets back is a handle into that partition:
// a class that has sent nothing calls the minter as class SQL and reads SQL's responses out of the
// handle. Partitioning the read side and leaving the write side open undoes the partitioning.
//
// WHY THIS IS A PACKAGE AND NOT A FLAG, A CHECK OR A COMMENT. Three previous rounds of this fight
// were lost to guards, and the lesson each time was the same: a check is code, and the next file
// can be written around it. Go has exactly one construct that the compiler enforces and that no
// amount of cleverness inside another package can route around, and it is the INTERNAL rule:
//
//	server/utils/internal/triagecap is importable by, and only by, packages rooted at server/utils.
//
// The runner and the type layer live under server/utils, so they can name Runner and call Grant.
// The classifiers live at server/triageclasses, OUTSIDE that subtree, so `go build` refuses the
// import with "use of internal package ... not allowed". That refusal is not a test that somebody
// has to keep running; it is the build.
//
// THE SUBTREE RULE IS THE WHOLE TRICK, SO NOTE IT CAREFULLY. a/b/internal/c is importable by
// everything under a/b, which is why the classifiers had to move out of server/utils/triage. While
// they lived there they were rooted at server/utils and the internal rule would have waved them
// straight through.
//
// WHY THE VALUE IS NOT AN EMPTY STRUCT. A class cannot NAME this type, but it can obtain the type
// by reflection: reflect.TypeOf(triage.NewPerturbedVault).In(0) hands over the reflect.Type of the
// first parameter, reflect.New builds a zero value of it, and reflect.Value.Call then invokes the
// function with that zero value. Every holder of a Runner therefore has to be able to tell a
// granted one from a zero one, which means the grant has to be something reflect cannot synthesise
// from the outside. It is a POINTER to an allocation this package makes: reflect can build the
// pointer type, but it cannot Set an unexported field, so it cannot put the pointer into a Runner.
// Held reports false for the zero value and every caller fails closed on it.
package triagecap

// grant is the allocation a real capability points at. It carries a field rather than being empty
// because Go is allowed to give two zero-size allocations the same address, and it carries a
// sentinel so that a zeroed allocation reached some other way still reads as ungranted.
type grant struct{ sentinel uint64 }

// capSentinel is checked as well as the pointer so that memory that merely happens to be a
// non-nil *grant does not read as a capability.
const capSentinel = 0x7472696167655f31 // "triage_1"

// Runner is the capability the triage runner holds. Its zero value grants nothing.
//
// It is a value type and not an interface on purpose: an interface parameter would let a caller
// pass any implementation, and the point is that there is exactly one way to obtain one.
type Runner struct{ tok *grant }

// Grant issues a capability. Only code under server/utils can call it, because only code under
// server/utils can import this package.
func Grant() Runner { return Runner{tok: &grant{sentinel: capSentinel}} }

// Held reports whether this is a real capability. The zero value, and anything reflect can build
// from the outside, reports false.
func (r Runner) Held() bool { return r.tok != nil && r.tok.sentinel == capSentinel }
