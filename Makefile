# Makefile — PXAT PT2887-CI Ubuntu fingerprint driver
#
# Preferred (on the target machine, needs dev packages):
#   sudo apt install libfprint-2-tod-dev libusb-1.0-0-dev libglib2.0-dev \
#                    libgusb-dev libjson-glib-dev libgudev-1.0-dev pkg-config
#   make
#
# Offline / no-root build against a local sysroot of extracted .deb packages:
#   make SYSROOT=/path/to/sysroot
#
# The pre-built binaries in dist/ are already usable; `make` is optional.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -fPIC
DESTDIR ?=
PREFIX  ?= /usr/local

SYSROOT ?=
ifeq ($(strip $(SYSROOT)),)
  TOD_CFLAGS := $(shell pkg-config --cflags libfprint-2-tod-1 2>/dev/null)
  TOD_LIBS   := $(shell pkg-config --libs   libfprint-2-tod-1 2>/dev/null)
  USB_CFLAGS := $(shell pkg-config --cflags libusb-1.0 2>/dev/null)
  USB_LIBS   := $(shell pkg-config --libs   libusb-1.0 2>/dev/null)
  TOD_DIR    := $(shell pkg-config --variable=tod_driversdir libfprint-2-tod-1 2>/dev/null)
else
  S := $(SYSROOT)
  TOD_CFLAGS := -I$(S)/usr/include/libfprint-2/tod-1 \
                -I$(S)/usr/include/libfprint-2 \
                -I$(S)/usr/include/gusb-1 \
                -I$(S)/usr/include/libusb-1.0 \
                -I$(S)/usr/include/json-glib-1.0 \
                -I$(S)/usr/include/gio-unix-2.0 \
                -I$(S)/usr/include/glib-2.0 \
                -I$(S)/usr/lib/x86_64-linux-gnu/glib-2.0/include
  TOD_LIBS   := -L$(S)/usr/lib/x86_64-linux-gnu \
                -lfprint-2-tod -lfprint-2 -lgusb -lusb-1.0 \
                -lglib-2.0 -lgobject-2.0 -lgio-2.0
  USB_CFLAGS := -I$(S)/usr/include
  USB_LIBS   := -L$(S)/usr/lib/x86_64-linux-gnu -lusb-1.0
  TOD_DIR    := /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1
endif

.PHONY: all tools clean check

all: dist/libpxat_pt2887ci.so dist/pxat_probe

tools: dist/check_driver dist/enumerate_test

dist/libpxat_pt2887ci.so: src/pxat_pt2887ci.c
	@mkdir -p dist
	$(CC) -shared $(CFLAGS) -o $@ $< $(TOD_CFLAGS) $(TOD_LIBS)

dist/pxat_probe: tools/pxat_probe.c
	@mkdir -p dist
	$(CC) $(CFLAGS) -o $@ $< $(USB_CFLAGS) $(USB_LIBS)

dist/check_driver: tools/check_driver.c
	@mkdir -p dist
	$(CC) $(CFLAGS) -o $@ $< $(TOD_CFLAGS) $(TOD_LIBS) -ldl

dist/enumerate_test: tools/enumerate_test.c
	@mkdir -p dist
	$(CC) $(CFLAGS) -o $@ $< $(TOD_CFLAGS) $(TOD_LIBS)

# Verification that needs NO root and NO USB write access.
check: all tools
	@echo "--- [1/4] PXAT frame + CRC self-test ---"
	./dist/pxat_probe frames
	@echo "--- [2/4] exported TOD symbol ---"
	nm -D dist/libpxat_pt2887ci.so | grep fpi_tod_shared_driver_get_type
	@echo "--- [3/4] driver class registration ---"
	./dist/check_driver dist/libpxat_pt2887ci.so
	@echo "--- [4/4] real libfprint device enumeration ---"
	FP_TOD_DRIVERS_DIR="$(CURDIR)/dist" ./dist/enumerate_test

clean:
	rm -f dist/libpxat_pt2887ci.so dist/pxat_probe dist/check_driver dist/enumerate_test
