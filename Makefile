APP_NAME = kvas2
APP_DESCRIPTION = DNS-based routing application
APP_MAINTAINER = Vladimir Avtsenov <vladimir.lsk.cool@gmail.com>

TAG = $(shell git describe --tags --abbrev=0 2> /dev/null || git rev-parse --short HEAD)
COMMIT = $(shell git rev-parse --short HEAD)
COMMITS_SINCE_TAG = $(shell git rev-list ${TAG}..HEAD --count || echo "0")
VERSION ?= $(TAG)

ARCH ?= mipsel
GOOS ?= linux
GOARCH ?= mipsle
GOMIPS ?= softfloat
GOARM ?=

BUILD_DIR = ./.build
PKG_DIR = $(BUILD_DIR)/$(ARCH)
BIN_DIR = $(PKG_DIR)/data/opt/usr/bin
PARAMS = -v -a -trimpath -ldflags="-X 'kvas2/constant.Version=$(VERSION)' -X 'kvas2/constant.Commit=$(COMMIT)' -w -s"

all: build_daemon package

build_daemon:
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOMIPS=$(GOMIPS) GOARM=$(GOARM) go build $(PARAMS) -o $(BIN_DIR)/kvas2d ./cmd/kvas2d

package:
	@mkdir -p $(PKG_DIR)/control
	@echo '2.0' > $(PKG_DIR)/debian-binary
	@echo 'Package: $(APP_NAME)' > $(PKG_DIR)/control/control
	@echo 'Version: $(VERSION)-$(COMMITS_SINCE_TAG)' >> $(PKG_DIR)/control/control
	@echo 'Architecture: $(ARCH)' >> $(PKG_DIR)/control/control
	@echo 'Maintainer: $(APP_MAINTAINER)' >> $(PKG_DIR)/control/control
	@echo 'Description: $(APP_DESCRIPTION)' >> $(PKG_DIR)/control/control
	@echo 'Section: base' >> $(PKG_DIR)/control/control
	@echo 'Priority: optional' >> $(PKG_DIR)/control/control
	@echo 'Depends: libc, iptables, socat' >> $(PKG_DIR)/control/control
	@mkdir -p $(PKG_DIR)/data/opt/usr/bin
	@cp -r ./opt $(PKG_DIR)/data/
	@fakeroot sh -c "tar -C $(PKG_DIR)/control -czvf $(PKG_DIR)/control.tar.gz ."
	@fakeroot sh -c "tar -C $(PKG_DIR)/data -czvf $(PKG_DIR)/data.tar.gz ."
	@tar -C $(PKG_DIR) -czvf $(BUILD_DIR)/$(APP_NAME)_$(ARCH).ipk ./debian-binary ./control.tar.gz ./data.tar.gz
