# Common makefile -- loads make rules for each platform

OSTYPE=$(shell uname -s)

ifeq ($(OSTYPE),Darwin)
	include make-mac.mk
endif

ifeq ($(OSTYPE),Linux)
	include make-linux.mk
endif

ifeq ($(OSTYPE),FreeBSD)
	CC=clang
	CXX=clang++
	ZT_BUILD_PLATFORM=7
	include make-bsd.mk
endif
ifeq ($(OSTYPE),OpenBSD)
	CC=clang
	CXX=clang++
	ZT_BUILD_PLATFORM=9
	include make-bsd.mk
endif

ifeq ($(OSTYPE),NetBSD)
	include make-netbsd.mk
endif

drone:
	@echo "rendering .drone.yaml from .drone.jsonnet"
	drone jsonnet --format --stream
	drone sign zerotier/ZeroTierOne --save

clang-format:
	find node osdep service tcp-proxy nonfree/controller -iname '*.cpp' -o -iname '*.hpp' | xargs clang-format -i

WINDOWS_OUT_DIR ?= build/windows-x64
WINDOWS_INSTALLER ?= $(WINDOWS_OUT_DIR)/ZeroTier-One-x64-Installer.exe
REMOTE_HOST ?= vicco
PI_HOST ?= pi3
PI_INSTALL_STAGE_DIR ?= /var/tmp/zerotier-remote-install

.PHONY: windows windows-install pi-install

windows:
	tools/windows-cross/build-and-package.sh "$(WINDOWS_OUT_DIR)" "$(WINDOWS_INSTALLER)"

windows-install:
	tools/windows-cross/remote-install.sh "$(REMOTE_HOST)" "$(WINDOWS_INSTALLER)"

pi-install:
	tools/pi-install.sh "$(PI_HOST)" "$(PI_INSTALL_STAGE_DIR)"
