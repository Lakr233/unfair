PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
PRODUCT := unfair-swift
INSTALL_NAME := unfair
BUILD_DIR := .build/release

.PHONY: all build install uninstall clean

all: build

build:
	swift build -c release --product $(PRODUCT)

install: build
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 "$(BUILD_DIR)/$(PRODUCT)" "$(DESTDIR)$(BINDIR)/$(INSTALL_NAME)"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(INSTALL_NAME)"

clean:
	swift package clean
