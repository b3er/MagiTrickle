APP_NAME = magitrickle
APP_DESCRIPTION = DNS-based routing application
APP_MAINTAINER = Vladimir Avtsenov <vladimir.lsk.cool@gmail.com>

COMMIT = $(shell git rev-parse --short HEAD)
UPSTREAM_VERSION ?= $(shell git describe --tags --abbrev=0 2> /dev/null || echo $(COMMIT))
OPKG_REVISION = ~git$(shell date +%Y%m%d).$(COMMIT)-1
ifeq ($(shell git rev-parse --abbrev-ref HEAD), main)
	TAG = $(shell git describe --tags --abbrev=0 2> /dev/null || echo $(COMMIT))
	COMMITS_SINCE_TAG = $(shell git rev-list ${TAG}..HEAD --count || echo "0")
	OPKG_REVISION = -$(shell expr $(COMMITS_SINCE_TAG) + 1)
endif

ARCH ?= mipsel
GOOS ?= linux
GOARCH ?= mipsle
GOMIPS ?= softfloat
GOARM ?=

BUILD_DIR = ./.build
PKG_DIR = $(BUILD_DIR)/$(ARCH)
BIN_DIR = $(PKG_DIR)/data/opt/bin
PARAMS = -v -a -trimpath -ldflags="-X 'magitrickle/constant.Version=$(UPSTREAM_VERSION)$(OPKG_REVISION)' -X 'magitrickle/constant.Commit=$(COMMIT)' -w -s"

all: clear build_daemon package

clear:
	rm -rf $(PKG_DIR)

build_daemon:
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOMIPS=$(GOMIPS) GOARM=$(GOARM) go build $(PARAMS) -o $(BIN_DIR)/magitrickled ./cmd/magitrickled

package:
	@mkdir -p $(PKG_DIR)/control
	@echo '2.0' > $(PKG_DIR)/debian-binary
	@echo 'Package: $(APP_NAME)' > $(PKG_DIR)/control/control
	@echo 'Version: $(UPSTREAM_VERSION)$(OPKG_REVISION)' >> $(PKG_DIR)/control/control
	@echo 'Architecture: $(ARCH)' >> $(PKG_DIR)/control/control
	@echo 'Maintainer: $(APP_MAINTAINER)' >> $(PKG_DIR)/control/control
	@echo 'Description: $(APP_DESCRIPTION)' >> $(PKG_DIR)/control/control
	@echo 'Section: net' >> $(PKG_DIR)/control/control
	@echo 'Priority: optional' >> $(PKG_DIR)/control/control
	@echo 'Depends: libc, iptables, socat' >> $(PKG_DIR)/control/control
	@cp -r ./opt $(PKG_DIR)/data/
	@fakeroot sh -c "tar -C $(PKG_DIR)/control -czvf $(PKG_DIR)/control.tar.gz ."
	@fakeroot sh -c "tar -C $(PKG_DIR)/data -czvf $(PKG_DIR)/data.tar.gz ."
	@tar -C $(PKG_DIR) -czvf $(BUILD_DIR)/$(APP_NAME)_$(ARCH).ipk ./debian-binary ./control.tar.gz ./data.tar.gz
