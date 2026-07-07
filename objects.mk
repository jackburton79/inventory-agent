USER_OBJS :=

LIBS := -lz -lcrypto -lssl

CFLAGS := -fPIE -O2 -Wall \
	-DUSE_SSL \
	-DOPENSSL_API_3_0 \
	-I./ \
	-Ilibs/ \
	-Ilibs/civetweb-1.16/include \
	-Ilibs/civetweb-1.16/src

CXXFLAGS := $(CFLAGS) 
