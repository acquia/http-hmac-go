GOPATH:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
export GOPATH

GOVERSION:=$(shell go version | grep 1.16)

.PHONY: goversion
goversion:
	@if [ -z "${GOVERSION}" ]; then \
		echo "Please install GO 1.16 or lower to run the test cases.";\
		exit 1;\
	fi\

.PHONY: dependency
dependency:
	@go get -t ./...

.PHONY: test
test: goversion dependency
	@go test -race -v ./...

.PHONY: coverage
coverage: goversion dependency
	@go test -race -cover ./...