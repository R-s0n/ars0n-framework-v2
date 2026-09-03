// The oracle is its own module so that main_test.go can run.
//
// It used to be created inside the Dockerfile with `go mod init oracle`, which built fine but left
// the source untestable outside docker: the emulations in main.go are the thing every positive
// control depends on, and they were only ever checked by running a scanner at a container. Standard
// library only, no requires, so this file exists purely to make `go test ./...` work here.
module oracle

go 1.23
