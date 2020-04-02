# Goals:
# - user can build binaries on their system without having to install special tools
# - user can fork the canonical repo and expect to be able to run CircleCI checks
#
# This makefile is meant for humans

## In concourse, before release, tag is of format 'vrc-1585761231-0.1.3-f6d7b72'
## after release,it is of format 'v0.1.3'. Code below will work for both format
## as cut will return the string if no delimiters are found
VERSION := $(shell git describe --tags --always | cut -d- -f 3 | tr -d 'v')
LDFLAGS := -ldflags='-X "main.Version=$(VERSION)"'
DARWIN_BUILD_ARGS := ""

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	ifneq ("$(wildcard /osxcross/target/bin/x86_64-apple-darwin14-cc)","")
	  DARWIN_BUILD_FLAGS += CC=/osxcross/target/bin/x86_64-apple-darwin14-cc CGO_ENABLED=1
  endif
endif

test:
	GO111MODULE=on go test -mod=vendor -covermode=count -coverprofile=coverage.out -v ./...
	@echo
	@echo INFO: to launch the coverage report: go tool cover -html=coverage.out
##
## More information about cover reports:
## https://blog.golang.org/cover

staticcheck:
	go vet
	staticcheck cmd/*.go
	staticcheck lib/client/*.go
	staticcheck lib/client/mfa/*.go
	staticcheck lib/provider/*.go

sec-lib:
	gosec lib/provider/
	gosec lib/client/
	gosec lib/client/mfa/
	gosec lib/client/types/

sec-cli:
	gosec cmd/

all: linux darwin
linux: dist/aws-okta-$(VERSION)-linux-amd64
darwin: dist/aws-okta-$(VERSION)-darwin-amd64

clean:
	rm -rf ./dist
	rm -f coverage.out

dist/:
	mkdir -p dist

dist/aws-okta-$(VERSION)-darwin-amd64: | dist/
	$(DARWIN_BUILD_FLAGS) GOOS=darwin GOARCH=amd64 GO111MODULE=on go build -mod=vendor $(LDFLAGS) -o $@

dist/aws-okta-$(VERSION)-linux-amd64: | dist/
	GOOS=linux GOARCH=amd64 GO111MODULE=on go build -mod=vendor $(LDFLAGS) -o $@

.PHONY: clean all linux darwin test
