# Makefile for inventory-agent
#
# Targets:
#   all (default)  build the agent and the test programs
#   agent          build only the agent
#   check          build and run the unit tests
#   install        install the agent in $(DESTDIR)$(BINDIR), stripped
#   uninstall      remove the installed agent
#   clean          remove all build products
#
# Variables:
#   CC, CXX, CFLAGS, CXXFLAGS, CPPFLAGS, LDFLAGS, LDLIBS  usual meaning
#   PREFIX (/usr/local), BINDIR ($(PREFIX)/bin), DESTDIR   install paths
#   INSTALL_STRIP=  install without stripping the symbols (default: -s)
#   DEBUG=1   build without optimizations, with debug info and -DDEBUG=1
#             (run "make clean" when switching between debug and release)
#   WEBSERVER=0  build without the web server of the daemon mode
#             (run "make clean" when switching)
#   V=1       show the full compiler command lines

PROGRAM := ocsinventory-agent
TESTS := test/urltest test/zlibtest test/httptest test/configtest test/edidtest test/processors-info-test

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
INSTALL ?= install
INSTALL_STRIP ?= -s

BUILDDIR := build

ifeq ($(DEBUG),1)
OPTFLAGS := -O0 -g -DDEBUG=1
else
# Optimize for size: the agent is not performance critical
OPTFLAGS := -Os
endif

CFLAGS ?= $(OPTFLAGS)
CXXFLAGS ?= $(OPTFLAGS)

WARNINGS := -Wall
PROJECT_WARNINGS := $(WARNINGS) -Wextra -Wno-unused-parameter

override CPPFLAGS += -I. -Ilibs -Ilibs/civetweb-1.16/include
override CXXFLAGS += -std=c++17
LDLIBS += -lz -lssl -lcrypto -ldl -lpthread

# Put every function and variable in its own section, so that the
# linker can discard the unused ones
SECTION_FLAGS := -ffunction-sections -fdata-sections
override CFLAGS += $(SECTION_FLAGS)
override CXXFLAGS += $(SECTION_FLAGS)
override LDFLAGS += -Wl,--gc-sections

WEBSERVER ?= 1

# Project sources
AGENT_SRCS := $(filter-out main.cpp,$(wildcard *.cpp)) \
	$(wildcard backends/*.cpp) \
	$(wildcard http/*.cpp)

# Third party sources
EDID_SRCS := edid-decode.c
TINYXML2_SRCS := libs/tinyxml2/tinyxml2.cpp
CIVETWEB_SRCS := libs/civetweb-1.16/src/civetweb.c

ifeq ($(WEBSERVER),0)
AGENT_SRCS := $(filter-out WebServer.cpp,$(AGENT_SRCS))
CIVETWEB_SRCS :=
override CPPFLAGS += -DNO_WEBSERVER
endif

CIVETWEB_FLAGS := -Ilibs/civetweb-1.16/src \
	-DUSE_SSL \
	-DOPENSSL_API_3_0 \
	-DNO_CGI \
	-DNO_LUA \
	-DNO_DUKTAPE \
	-DNO_WEBSOCKET
TINYXML2_FLAGS := -DTIXML_USE_STL

obj = $(addprefix $(BUILDDIR)/,$(addsuffix .o,$(basename $(1))))

AGENT_OBJS := $(call obj,$(AGENT_SRCS))
LIB_OBJS := $(call obj,$(EDID_SRCS) $(TINYXML2_SRCS) $(CIVETWEB_SRCS))
COMMON_OBJS := $(AGENT_OBJS) $(LIB_OBJS)
MAIN_OBJ := $(call obj,main.cpp)
TEST_OBJS := $(call obj,$(addsuffix .cpp,$(TESTS)))
ALL_OBJS := $(COMMON_OBJS) $(MAIN_OBJ) $(TEST_OBJS)

ifeq ($(V),1)
Q :=
else
Q := @
endif


.PHONY: all agent check install uninstall clean OcsInventory-ng-agent

all: $(PROGRAM) $(TESTS)

agent: $(PROGRAM)

# Kept for compatibility with existing build scripts
OcsInventory-ng-agent: $(PROGRAM)

$(PROGRAM): $(COMMON_OBJS) $(MAIN_OBJ)
	@echo "  LD      $@"
	$(Q)$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TESTS): test/%: $(BUILDDIR)/test/%.o $(COMMON_OBJS)
	@echo "  LD      $@"
	$(Q)$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

check: test/urltest test/zlibtest test/httptest test/configtest test/edidtest
	./test/urltest
	./test/zlibtest
	./test/httptest
	./test/configtest
	./test/edidtest

install: $(PROGRAM)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) $(INSTALL_STRIP) -m 755 $(PROGRAM) $(DESTDIR)$(BINDIR)/$(PROGRAM)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROGRAM)

clean:
	rm -rf $(BUILDDIR) $(PROGRAM) $(TESTS)


# Per-target flags
$(AGENT_OBJS) $(MAIN_OBJ) $(TEST_OBJS): EXTRA_FLAGS := $(PROJECT_WARNINGS)
$(call obj,$(EDID_SRCS)): EXTRA_FLAGS := $(WARNINGS)
$(call obj,$(TINYXML2_SRCS)): EXTRA_FLAGS := $(WARNINGS) $(TINYXML2_FLAGS)
$(call obj,$(CIVETWEB_SRCS)): EXTRA_FLAGS := $(WARNINGS) $(CIVETWEB_FLAGS)

# -MMD -MP generate the header dependencies (.d files) while compiling
$(BUILDDIR)/%.o: %.cpp
	@mkdir -p $(@D)
	@echo "  CXX     $<"
	$(Q)$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(EXTRA_FLAGS) -MMD -MP -c -o $@ $<

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(@D)
	@echo "  CC      $<"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_FLAGS) -MMD -MP -c -o $@ $<

-include $(ALL_OBJS:.o=.d)
