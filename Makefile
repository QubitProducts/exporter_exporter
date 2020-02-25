GITHUB_ORG  = QubitProducts
GITHUB_REPO = exporter_exporter
VERSION     = 0.3.1

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

PACKAGE_NAME       = expexp
PACKAGE_VERSION    = $(VERSION)
PACKAGE_REVISION   = 3
PACKAGE_ARCH       = amd64
PACKAGE_MAINTAINER = tristan@qubit.com
PACKAGE_FILE       = $(PACKAGE_NAME)_$(PACKAGE_VERSION)-$(PACKAGE_REVISION)_$(PACKAGE_ARCH)
BINNAME            = exporter_exporter

PWD := $(shell pwd)

all: clean build/$(BINNAME)-$(VERSION).linux-amd64/$(BINNAME) build/$(BINNAME)-$(VERSION).windows-amd64/$(BINNAME) build/$(BINNAME)-$(VERSION).darwin-amd64/$(BINNAME)
clean:
	rm -f $(PACKAGE_FILE).{deb,rpm,nupkg}
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

.PHONY: AUTHORS
AUTHORS:
	# There's only so much credit I need.
	git log --format='%aN <%aE>' | grep -v Tristan\ Colgate\  | sort -u > AUTHORS

.PHONY: prepare-package-deb prepare-package-rpm clean-package
prepare-package-deb: clean-package-deb build/$(BINNAME)-$(VERSION).linux-amd64/$(BINNAME)
	mkdir -p dist/deb/{usr/local/bin,etc/init,etc/default,etc/exporter_exporter.d}
	install -m755 build/$(BINNAME)-$(VERSION).linux-amd64/$(BINNAME) dist/deb/usr/local/bin/$(BINNAME)
	install -m644 package/deb/$(BINNAME).conf dist/deb/etc/init/$(BINNAME).conf
	install -m644 package/deb/$(BINNAME).defaults dist/deb/etc/default/$(BINNAME)
	install -m644 expexp.yaml dist/deb/etc/expexp.yaml
	touch dist/deb/etc/exporter_exporter.d/.dir

prepare-package-rpm: clean-package-rpm build/$(BINNAME)-$(VERSION).linux-amd64/$(BINNAME)
	mkdir -p dist/rpm/{var/log/exporter_exporter,usr/local/bin,usr/lib/systemd/system,etc/sysconfig}
	install -m755 build/$(BINNAME)-$(VERSION).linux-amd64/$(BINNAME) dist/rpm/usr/local/bin/$(BINNAME)
	install -m644 package/rpm/$(BINNAME) dist/rpm/etc/sysconfig/$(BINNAME)
	install -m644 package/rpm/$(BINNAME).service dist/rpm/usr/lib/systemd/system/$(BINNAME).service
	install -m644 expexp.yaml dist/rpm/etc/expexp.yaml

clean-package-%:
	rm -f $(PACKAGE_FILE).$*
	rm -rf dist

$(PACKAGE_FILE)-deb: prepare-package-deb
	  fpm \
	  -C dist/deb \
	  -t deb \
	  -m $(PACKAGE_MAINTAINER) \
	  -n $(PACKAGE_NAME) \
	  -a $(PACKAGE_ARCH) \
	  -v $(PACKAGE_VERSION) \
	  --iteration $(PACKAGE_REVISION) \
	  --config-files /etc/expexp.yaml \
	  --config-files /etc/init/$(BINNAME).conf \
	  --config-files /etc/default/$(BINNAME) \
	  -s dir \
	  -p $(PACKAGE_FILE).deb \
	  .

$(PACKAGE_FILE)-rpm: prepare-package-rpm
	  fpm \
	  -C dist/rpm \
	  -t rpm \
	  -m $(PACKAGE_MAINTAINER) \
	  -n $(PACKAGE_NAME) \
	  -a $(PACKAGE_ARCH) \
	  -v $(PACKAGE_VERSION) \
	  --iteration $(PACKAGE_REVISION) \
	  --config-files /etc/expexp.yaml \
	  --config-files /etc/sysconfig/$(BINNAME) \
	  -s dir \
	  -p $(PACKAGE_FILE).rpm \
	  .

$(PACKAGE_FILE)-nupkg: clean-package build/$(BINNAME)-$(VERSION).windows-amd64/$(BINNAME).exe
	docker run -v $(PWD):/$(BINNAME) patrickhuber/choco-linux:latest \
	choco pack --outputdirectory /$(BINNAME) --version=${PACKAGE_VERSION} bin=$(BINNAME) /$(BINNAME)/package/nupkg/$(BINNAME).nuspec

.PHONY: build-docker release-docker
build-docker: 
	docker build -t $(DOCKER_IMAGE) .

release-docker: build-docker
	docker push $(DOCKER_IMAGE)
	docker tag $(DOCKER_IMAGE) $(DOCKER_IMAGE_LATEST)
	docker push $(DOCKER_IMAGE_LATEST)

LDFLAGS = -X main.Version=$(VERSION) \
					-X main.Branch=$(BRANCH) \
					-X main.Revision=$(REVISION) \
					-X main.BuildUser=$(BUILDUSER) \
					-X main.BuildDate=$(BUILDDATE)

build/$(BINNAME)-$(VERSION).windows-amd64/$(BINNAME).exe: $(SRCS)
	GOOS=windows GOARCH=amd64 $(GO) build \
	 -ldflags "$(LDFLAGS)" \
	 -o $@ \
	 .

build/$(BINNAME)-$(VERSION).windows-amd64.zip: build/expoter_exporter-$(VERSION).windows-amd64/$(BINNAME).exe
	zip $@ $<

build/$(BINNAME)-$(VERSION).%-amd64/$(BINNAME): $(SRCS)
	GOOS=$* GOARCH=amd64 $(GO) build \
	 -ldflags  "$(LDFLAGS)" \
	 -o $@ \
	 .

build/$(BINNAME)-$(VERSION).%-amd64.tar.gz: build/$(BINNAME)-$(VERSION).%-amd64/$(BINNAME)
	cd build && \
		tar cfzv $(BINNAME)-$(VERSION).$*-amd64.tar.gz $(BINNAME)-$(VERSION).$*-amd64

.PHONY: package-deb package-rpm package-nupkg
package-deb: $(PACKAGE_FILE)-deb
package-rpm: $(PACKAGE_FILE)-rpm
package-nupkg: $(PACKAGE_FILE)-nupkg

release-package-nupkg: PACKAGE_FILE=$(BINNAME)
release-package-%: $(PACKAGE_FILE)-%
	go run github.com/aktau/github-release upload \
	  -u $(GITHUB_ORG) \
	 	-r $(GITHUB_REPO) \
	 	--tag v$(VERSION) \
		--name $(PACKAGE_FILE).$* \
		--file $(PACKAGE_FILE).$*

release-windows: build/exporter_exporter-$(VERSION).windows-amd64.zip
	go run github.com/aktau/github-release upload \
		-u $(GITHUB_ORG) \
		-r $(GITHUB_REPO) \
		--tag v$(VERSION) \
		--name exporter_exporter-$(VERSION).windows-amd64.zip \
		-f ./build/exporter_exporter-$(VERSION).windows-amd64.zip

release-%: build/exporter_exporter-$(VERSION).%-amd64.tar.gz
	go run github.com/aktau/github-release upload \
		-u $(GITHUB_ORG) \
		-r $(GITHUB_REPO) \
		--tag v$(VERSION) \
		--name exporter_exporter-$(VERSION).$*-amd64.tar.gz \
		-f ./build/exporter_exporter-$(VERSION).$*-amd64.tar.gz

release: 
	git tag v$(VERSION)
	git push origin v$(VERSION)
	go run github.com/aktau/github-release release \
		-u $(GITHUB_ORG) \
		-r $(GITHUB_REPO) \
		--tag v$(VERSION) \
		--name v$(VERSION)
	make release-darwin release-linux release-windows release-package-deb release-package-rpm release-package-nupkg