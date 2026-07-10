USER_OBJS :=

LIBS := -lz -lcrypto -lssl -ldl

CFLAGS := -fPIE -O2 -Wall \
	-DUSE_SSL \
	-DOPENSSL_API_3_0 \
	-DNO_CGI \
	-DNO_LUA \
	-DNO_DUKTAPE \
	-DNO_WEBSOCKET \
	-I./ \
	-Ilibs/ \
	-Ilibs/civetweb-1.16/include \
	-Ilibs/civetweb-1.16/src

CXXFLAGS := $(CFLAGS) 
