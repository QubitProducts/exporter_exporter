SHELL        := /usr/bin/env bash
GO           := go

all: build

clean:
	rm -rf dist

.PHONY: test
test:
	echo ">> running short tests"
	$(GO) test -short $(pkgs)

.PHONY: test-static
test-static:
	echo ">> running static tests"
	$(GO) vet $(pkgs)
	[[ "$(shell gofmt -l $(files))" == "" ]] || (echo "gofmt check failed"; exit 1)

.PHONY: format
format:
	echo ">> formatting code"
	$(GO) fmt $(pkgs)

.PHONY: vet
vet:
	echo ">> vetting code"
	$(GO) vet $(pkgs)

.PHONY: AUTHORS
AUTHORS:
	# There's only so much credit I need.
	git log --format='%aN <%aE>' | grep -v Tristan\ Colgate\  | sort -u > AUTHORS

.PHONY: build
build: vet format test
	go run github.com/goreleaser/goreleaser@latest release --snapshot --skip=publish --clean

.PHONY: release
release:
	go run github.com/goreleaser/goreleaser@latest release
