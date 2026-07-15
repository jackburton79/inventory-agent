USER_OBJS :=

LIBS := -lz -lcrypto -lssl
LIBS += -ldl -lpthread

CFLAGS := -fPIE -O2 -Wall \
	-I./ \
	-Ilibs/ \
	-Ilibs/civetweb-1.16/include \
	-Ilibs/civetweb-1.16/src

CXXFLAGS := $(CFLAGS) 
