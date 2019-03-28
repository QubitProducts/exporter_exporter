GITHUB_ORG  = QubitProducts
GITHUB_REPO = exporter_exporter

DOCKER_REGISTRY     = qubitproducts
DOCKER_NAME         = exporter_exporter
DOCKER_IMAGE        = $(DOCKER_REGISTRY)/$(DOCKER_NAME):$(VERSION)
DOCKER_IMAGE_LATEST = $(DOCKER_REGISTRY)/$(DOCKER_NAME):latest

SHELL        := /usr/bin/env bash
GO           := go
FIRST_GOPATH := $(firstword $(subst :, ,$(GOPATH)))
FILES         = $(shell find . -name '*.go' | grep -v vendor)
PREFIX       ?= $(shell pwd)
BIN_DIR      ?= $(shell pwd)
VERSION      ?= $(shell cat VERSION)

PACKAGE_TARGET     = deb
PACKAGE_NAME       = expexp
PACKAGE_VERSION    = $(shell cat VERSION)
PACKAGE_REVISION   = 3
PACKAGE_ARCH       = amd64
PACKAGE_MAINTAINER = tristan@qubit.com
PACKAGE_FILE       = $(PACKAGE_NAME)_$(PACKAGE_VERSION)-$(PACKAGE_REVISION)_$(PACKAGE_ARCH).$(PACKAGE_TARGET)
BINNAME            = exporter_exporter

PWD := $(shell pwd)

all: package
clean:
	rm -f $(PACKAGE_FILE)
	rm -rf dist
	rm -rf build

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

vendor: go.mod go.sum
	go mod vendor

.PHONY: build
build: vendor promu
	echo ">> building binaries"
	./promu build --prefix $(PREFIX)

.PHONY: tarball
tarball: promu
	echo ">> building release tarball"
	./promu tarball --prefix $(PREFIX) $(BIN_DIR)

.PHONY: promu
promu:
	echo ">> fetching promu"
	GOOS=$(shell uname -s | tr A-Z a-z) \
	GOARCH=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))) \
	$(GO) build -o promu github.com/prometheus/promu

.PHONY: github-release
github-release:
	echo ">> fetching github-release"
	GOOS=$(shell uname -s | tr A-Z a-z) \
	GOARCH=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))) \
	$(GO) build -o github-release github.com/aktau/github-release

.PHONY: release
release: promu github-release package
	echo ">> crossbuilding binaries"
	./promu crossbuild
	echo ">> crossbuilding tarballs"
	./promu crossbuild tarballs
	echo ">> creating github release"
	./github-release release -u $(GITHUB_ORG) -r $(GITHUB_REPO) --tag v$(VERSION) --name v$(VERSION)
	echo ">> uploading artifacts"
	./promu release .tarballs
	echo ">> uploading deb"
	./github-release upload -u $(GITHUB_ORG) -r $(GITHUB_REPO) --tag v$(VERSION) --name $(PACKAGE_FILE) --file $(PACKAGE_FILE)

.PHONY: prepare-package clean-package package
prepare-package: clean-package
	echo ">> crossbuilding binaries"
	./promu crossbuild -p linux/amd64
	mkdir -p dist/usr/local/bin
	mkdir -p dist/etc/init
	mkdir -p dist/etc/default
	mkdir -p dist/etc/exporter_exporter.d/
	install -m755 .build/linux-amd64/$(BINNAME) dist/usr/local/bin/$(BINNAME)
	install -m644 $(BINNAME).conf dist/etc/init/$(BINNAME).conf
	install -m644 $(BINNAME).defaults dist/etc/default/$(BINNAME)
	install -m644 expexp.yaml dist/etc/exporter_exporter.yaml
	touch dist/etc/exporter_exporter.d/.dir

clean-package:
	rm -rf dist

package: prepare-package
	cd dist && \
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

.PHONY: build-docker release-docker
build-docker: 
	docker build -t $(DOCKER_IMAGE) .

release-docker: build-docker
	docker push $(DOCKER_IMAGE)
	docker tag $(DOCKER_IMAGE) $(DOCKER_IMAGE_LATEST)
	docker push $(DOCKER_IMAGE_LATEST)
