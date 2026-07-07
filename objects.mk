USER_OBJS :=

LIBS := -lz -lcrypto -lssl

CFLAGS := -fPIE
CXXFLAGS := $(CFLAGS) -O2 -Wall -I ./ -I ./libs/ 
