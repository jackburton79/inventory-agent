# Build on Haiku with gcc.
#   make          build the kernel driver and the "backlight" tool
#   make install  install the driver in ~/config/non-packaged (then reboot)
CC ?= gcc
CFLAGS ?= -O2 -Wall
DRIVER := thinkpad_backlight
DRIVERDIR := $(HOME)/config/non-packaged/add-ons/kernel/drivers

all: $(DRIVER) backlight

$(DRIVER): thinkpad_backlight.c thinkpad_backlight.h
	$(CC) $(CFLAGS) -D_KERNEL_MODE -no-fpic -c -o $(DRIVER).o thinkpad_backlight.c
	$(CC) -o $@ -nostart -Wl,-soname=$(DRIVER) $(DRIVER).o \
		/boot/system/develop/lib/_KERNEL_

backlight: backlight.c thinkpad_backlight.h
	$(CC) $(CFLAGS) -o $@ backlight.c

install: all
	mkdir -p $(DRIVERDIR)/bin $(DRIVERDIR)/dev/misc
	cp $(DRIVER) $(DRIVERDIR)/bin/
	ln -sf ../../bin/$(DRIVER) $(DRIVERDIR)/dev/misc/$(DRIVER)

clean:
	rm -f $(DRIVER) $(DRIVER).o backlight

.PHONY: all install clean
