GITHUB_ORG  = QubitProducts
GITHUB_REPO = exporter_exporter

SHELL        := /usr/bin/env bash
GO           := GO15VENDOREXPERIMENT=1 go
FIRST_GOPATH := $(firstword $(subst :, ,$(GOPATH)))
PROMU        := $(FIRST_GOPATH)/bin/promu
PKGS          = $(shell $(GO) list $(shell glide nv))
FILES         = $(shell find . -name '*.go' | grep -v vendor)
PREFIX       ?= $(shell pwd)
BIN_DIR      ?= $(shell pwd)

PACKAGE_TARGET     = deb
PACKAGE_NAME       = expexp
PACKAGE_VERSION    = $(shell cat VERSION)
PACKAGE_REVISION   = 3
PACKAGE_ARCH       = amd64
PACKAGE_MAINTAINER = tristan@qubit.com
PACKAGE_FILE       = $(PACKAGE_NAME)_$(PACKAGE_VERSION)-$(PACKAGE_REVISION)_$(PACKAGE_ARCH).$(PACKAGE_TARGET)
BINNAME            = exporter_exporter

PWD := $(shell pwd)

# V := 1 # When V is set, print commands and build progress.
Q := $(if $V,,@)

all: package
clean:
	$Q rm -f $(PACKAGE_FILE)
	$Q rm -rf dist
	$Q rm -rf build

.PHONY: test
test:
	$Q echo ">> running short tests"
	$Q $(GO) test -short $(pkgs)

.PHONY: test-static
test-static:
	$Q echo ">> running static tests"
	$Q $(GO) vet $(pkgs)
	$Q [[ "$(shell gofmt -l $(files))" == "" ]] || (echo "gofmt check failed"; exit 1)

.PHONY: format
format:
	$Q echo ">> formatting code"
	$Q $(GO) fmt $(pkgs)

.PHONY: vet
vet:
	$Q echo ">> vetting code"
	$Q $(GO) vet $(pkgs)

.PHONY: build
build: promu
	$Q echo ">> building binaries"
	$Q $(PROMU) build --prefix $(PREFIX)

.PHONY: tarball
tarball: promu
	$Q echo ">> building release tarball"
	$Q $(PROMU) tarball --prefix $(PREFIX) $(BIN_DIR)

.PHONY: promu
promu:
	$Q echo ">> fetching promu"
	$Q GOOS=$(shell uname -s | tr A-Z a-z) \
	GOARCH=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))) \
	$(GO) get -u github.com/prometheus/promu

.PHONY: github-release
github-release:
	$Q echo ">> fetching github-release"
	$Q GOOS=$(shell uname -s | tr A-Z a-z) \
	GOARCH=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))) \
	$(GO) get -u github.com/aktau/github-release

.PHONY: release
release: promu github-release package
	$Q echo ">> crossbuilding binaries"
	$Q promu crossbuild
	$Q echo ">> crossbuilding tarballs"
	$Q promu crossbuild tarballs
	$Q echo ">> creating github release"
	$Q github-release release -u $(GITHUB_ORG) -r $(GITHUB_REPO) --tag v$(VERSION) --name v$(VERSION)
	$Q echo ">> uploading artifacts"
	$Q promu release .tarballs
	$Q echo ">> uploading deb"
	$Q github-release upload -u $(GITHUB_ORG) -r $(GITHUB_REPO) --tag v$(VERSION) --name $(PACKAGE_FILE) --file $(PACKAGE_FILE)

.PHONY: prepare-package clean-package package
prepare-package: clean-package
	$Q echo ">> crossbuilding binaries"
	$Q promu crossbuild -p linux/amd64
	$Q mkdir -p dist/usr/local/bin
	$Q mkdir -p dist/etc/init
	$Q mkdir -p dist/etc/default
	$Q mkdir -p dist/etc/exporter_exporter.d/
	$Q install -m755 .build/linux-amd64/$(BINNAME) dist/usr/local/bin/$(BINNAME)
	$Q install -m644 $(BINNAME).conf dist/etc/init/$(BINNAME).conf
	$Q install -m644 $(BINNAME).defaults dist/etc/default/$(BINNAME)
	$Q install -m644 expexp.yaml dist/etc/exporter_exporter.yaml
	$Q touch dist/etc/exporter_exporter.d/.dir

clean-package:
	$Q rm -rf dist

package: prepare-package
	$Q cd dist && \
	  fpm \
	  -t $(PACKAGE_TARGET) \
	  -m $(PACKAGE_MAINTAINER) \
	  -n $(PACKAGE_NAME) \
	  -a $(PACKAGE_ARCH) \
	  -v $(PACKAGE_VERSION) \
	  --iteration $(PACKAGE_REVISION) \
	  -s dir \
	  -p ../$(PACKAGE_FILE) \
	  .

