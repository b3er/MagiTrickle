-include .config

PKG_NAME := magitrickle
PKG_DESCRIPTION := DNS-based routing application
PKG_MAINTAINER := Vladimir Avtsenov <vladimir.lsk.cool@gmail.com>
PKG_RELEASE ?= 1

ifeq ($(strip $(PKG_VERSION)),)
	PKG_VERSION := $(shell git describe --tags --abbrev=0 2> /dev/null || echo "0.0.0")

	TAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
	COMMITS_SINCE_TAG := $(shell [ -n "$(TAG)" ] && git rev-list $(TAG)..HEAD --count 2>/dev/null || echo 0)
	ifneq ($(or $(COMMITS_SINCE_TAG),$(if $(TAG),,1)),0)
		PKG_VERSION_PRERELEASE := $(shell v=$(PKG_VERSION); echo $${v%.*}.$$(( $${v##*.} + 1 )) )
		PRERELEASE_DATE := $(shell date +%Y%m%d%H%M%S)
		COMMIT := $(shell git rev-parse --short HEAD)

		PKG_VERSION := $(PKG_VERSION_PRERELEASE)~git$(PRERELEASE_DATE).$(COMMIT)
	endif
endif

PLATFORM ?= entware
TARGET ?= aarch64-3.10
GOOS ?= linux
GOARCH ?= arm64
GOMIPS ?= softfloat
GOARM ?=
BUILDS_DIR := ./.build

BUILD_DIR := $(BUILDS_DIR)/$(TARGET)

DATA_DIR := $(BUILD_DIR)/data
CONTROL_DIR := $(BUILD_DIR)/control

BIN_DIR := $(DATA_DIR)/bin
ETC_DIR := $(DATA_DIR)/etc
USRSHARE_DIR := $(DATA_DIR)/usr/share
VARLIB_DIR := $(DATA_DIR)/var/lib

ifeq ($(PLATFORM),entware)
	BIN_DIR := $(DATA_DIR)/opt/bin
	ETC_DIR := $(DATA_DIR)/opt/etc
	USRSHARE_DIR := $(DATA_DIR)/opt/usr/share
	VARLIB_DIR := $(DATA_DIR)/opt/var/lib

	GO_TAGS += entware
	ifeq ($(filter %_kn,$(TARGET)),$(TARGET))
		GO_TAGS += entware_kn
	endif
endif

GO_FLAGS := \
	$(if $(GOOS),GOOS="$(GOOS)") \
	$(if $(GOARCH),GOARCH="$(GOARCH)") \
	$(if $(GOMIPS),GOMIPS="$(GOMIPS)")
GO_PARAMS = -v -trimpath -ldflags="-X 'magitrickle/constant.Version=$(PKG_VERSION)' -w -s" $(if $(GO_TAGS),-tags "$(GO_TAGS)")

all: clear build package

clear:
	rm -rf ./src/frontend/dist
	rm -rf "$(BUILD_DIR)"

build: build_backend build_frontend

build_backend:
	cd ./src/backend && go mod tidy
	mkdir -p "$(BIN_DIR)"
	cd ./src/backend && $(GO_FLAGS) go build $(GO_PARAMS) -o "../../$(BIN_DIR)/magitrickled" ./cmd/magitrickled
	upx -9 --lzma "$(BIN_DIR)/magitrickled"

build_frontend:
	cd ./src/frontend && npm install
	cd ./src/frontend && VITE_PKG_VERSION="$(PKG_VERSION)" VITE_PKG_VERSION_IS_DEV=$(if $(PKG_VERSION_PRERELEASE),true,false) npm run build
	mkdir -p "$(USRSHARE_DIR)/magitrickle/skins/default"
	cp -r ./src/frontend/dist/* "$(USRSHARE_DIR)/magitrickle/skins/default"

define _copy_files
	if [ -d $(1)/bin ]; then mkdir -p $(BIN_DIR); cp -r $(1)/bin/* $(BIN_DIR); fi
	if [ -d $(1)/etc ]; then mkdir -p $(ETC_DIR); cp -r $(1)/etc/* $(ETC_DIR); fi
	if [ -d $(1)/usr/share ]; then mkdir -p $(USRSHARE_DIR); cp -r $(1)/usr/share/* $(USRSHARE_DIR); fi
	if [ -d $(1)/var/lib ]; then mkdir -p $(VARLIB_DIR); cp -r $(1)/var/lib/* $(VARLIB_DIR); fi
endef

package:
	echo '2.0' > $(BUILD_DIR)/debian-binary

	mkdir -p $(BUILD_DIR)/control
	echo 'Package: $(PKG_NAME)' > $(BUILD_DIR)/control/control
	echo 'Version: $(PKG_VERSION)-$(PKG_RELEASE)' >> $(BUILD_DIR)/control/control
	echo 'Architecture: $(TARGET)' >> $(BUILD_DIR)/control/control
	echo 'Maintainer: $(PKG_MAINTAINER)' >> $(BUILD_DIR)/control/control
	echo 'Description: $(PKG_DESCRIPTION)' >> $(BUILD_DIR)/control/control
	echo 'Section: net' >> $(BUILD_DIR)/control/control
	echo 'Priority: optional' >> $(BUILD_DIR)/control/control
	echo 'Depends: libc, iptables, socat' >> $(BUILD_DIR)/control/control


	$(call _copy_files,./files/common)
	$(if $(filter entware,$(PLATFORM)), $(call _copy_files,./files/entware))
	$(if $(filter entware,$(PLATFORM)), $(if $(filter %_kn,$(TARGET)),$(call _copy_files,./files/entware_kn)))

	tar -C "$(BUILD_DIR)/control" -czvf "$(BUILD_DIR)/control.tar.gz" --owner=0 --group=0 .
	tar -C "$(BUILD_DIR)/data" -czvf "$(BUILD_DIR)/data.tar.gz" --owner=0 --group=0 .
	tar -C "$(BUILD_DIR)" -czvf "$(BUILDS_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_$(TARGET).ipk" --owner=0 --group=0 ./debian-binary ./control.tar.gz ./data.tar.gz
