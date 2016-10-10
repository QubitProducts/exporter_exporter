TARGET=deb
PACKAGE_NAME=expexp
PACKAGE_VERSION=0.2.0
PACKAGE_REVISION=1
PACKAGE_ARCH=amd64
PACKAGE_MAINTAINER=tristan@qubit.com
PACKAGE_FILE=$(PACKAGE_NAME)_$(PACKAGE_VERSION)-$(PACKAGE_REVISION)_$(PACKAGE_ARCH).$(TARGET)

GITREPO=https://github.com/QubitProducts/exporter_exporter.git

BINNAME=exporter_exporter

PWD=$(shell pwd)

all: package

binary: clean-binary
	go build .
	mkdir -p dist/usr/local/bin
	mkdir -p dist/etc/init
	mkdir -p dist/etc/default
	mkdir -p dist/etc/exporter_exporter.d/
	install -m755 $(BINNAME) dist//usr/local/bin/$(BINNAME)
	install -m644 $(BINNAME).conf dist/etc/init/$(BINNAME).conf
	install -m644 $(BINNAME).defaults dist/etc/default/$(BINNAME)
	install -m644 expexp.yaml dist/etc/exporter_exporter.yaml
	touch dist/etc/exporter_exporter.d/.dir
clean-binary:
	rm -f dist/usr/local/bin/$(BINNAME)

package: clean binary
	cd dist && \
	  fpm \
	  -t $(TARGET) \
	  -m $(PACKAGE_MAINTAINER) \
	  -n $(PACKAGE_NAME) \
	  -a $(PACKAGE_ARCH) \
	  -v $(PACKAGE_VERSION) \
	  --iteration $(PACKAGE_REVISION) \
	  -s dir \
	  -p ../$(PACKAGE_FILE) \
	  .


clean:
	rm -f $(PACKAGE_FILE)
	rm -rf dist
	rm -rf build
