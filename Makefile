#
#  Copyright (C) Canonical, Ltd.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 3.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

TOPDIR    := $(shell pwd)
BUILD     := ${TOPDIR}/build

# Vars for compiling Java sources
JAVA_SRC      := src/main/java/com/canonical/openssl
JAVA_SRC_DIRS := ${JAVA_SRC} ${JAVA_SRC}/drbg ${JAVA_SRC}/keyagreement ${JAVA_SRC}/keyencapsulation ${JAVA_SRC}/mac
JAVA_SRC_DIRS += ${JAVA_SRC}/kdf ${JAVA_SRC}/md ${JAVA_SRC}/signature ${JAVA_SRC}/key ${JAVA_SRC}/cipher
JAVA_SRC_DIRS += ${JAVA_SRC}/provider ${JAVA_SRC}/util
JAVA_FILES    = $(wildcard $(addsuffix /*.java, $(JAVA_SRC_DIRS)))

# Vars for compiling the C sources
JSSL_HEADERS    := -I${TOPDIR}/src/main/native/include -I${TOPDIR}/src/main/native/include/jni
JNI_HEADERS     := -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/
OPENSSL_HEADERS := -I/usr/local/include/openssl/
INCLUDE_HEADERS := ${JSSL_HEADERS} ${JNI_HEADERS} ${OPENSSL_HEADERS}

NATDIR   := ${TOPDIR}/src/main/native/c
NATFILES := $(foreach dir,$(NATDIR),$(wildcard $(dir)/*.c))
OBJS  := $(patsubst $(NATDIR)/%.c, $(BUILD)/bin/%.o, $(NATFILES))


CCFLAGS := ${INCLUDE_HEADERS} -c -fPIC -g
LDFLAGS := -shared -fPIC -Wl,-soname,libjssl.so
SOLIB   := $(BUILD)/bin/libjssl.so

# Vars for compiling the test sources
TEST_BIN := ${TOPDIR}/build/test/bin
TEST_C_DIR := ${TOPDIR}/src/test/native
TEST_C_SRCS := $(foreach dir,$(TEST_C_DIR),$(wildcard $(dir)/*.c))
TEST_C_OBJS := $(patsubst $(TEST_C_DIR)/%.c,$(TEST_BIN)/%,$(TEST_C_SRCS))
TEST_CFLAGS := ${INCLUDE_HEADERS} -L${BUILD}/bin -L/usr/local/lib64
TEST_JAVA_DIR := ${TOPDIR}/src/test/java
TEST_JAVA_SRCS := $(wildcard $(addsuffix /*.java, $(TEST_JAVA_DIR)))
TEST_NAT_SRCS := $(wildcard $(addsuffix /*.c, $(TEST_JAVA_DIR)/native))
TESTOBJS      := $(patsubst $(TEST_JAVA_DIR)/native/%.c, $(TEST_BIN)/%.o, $(TEST_NAT_SRCS))

LIBPATH := $(BUILD)/bin:${TOPDIR}/build/test/bin

$(BUILD)/bin:
	@mkdir -p $@

$(BUILD)/classes:
	@mkdir -p $@
	@mkdir -p $@/resources/native

$(BUILD)/test/bin:
	@mkdir -p $@

$(BUILD)/test/classes:
	@mkdir -p $@

$(BUILD)/bin/%.o: $(JNIDIR)/%.c
	@cc $(CCFLAGS) -o $@ $<

$(BUILD)/bin/%.o: $(NATDIR)/%.c
	@cc $(CCFLAGS) -o $@ $<

$(BUILD)/test/bin/%.o: $(TEST_JAVA_DIR)/native/%.c
	@cc $(CCFLAGS) -o $@ $<

$(SOLIB): $(OBJS)
	@cc ${LDFLAGS} -o $@ $^ -L/usr/local/lib64 -lcrypto -lssl

$(TEST_BIN)/%: $(TEST_C_DIR)/%.c
	@cc $(TEST_CFLAGS) -o $@ $< -ljssl -lcrypto

gen-code:
	@sh ${TOPDIR}/gen/gen-classes.sh

solib: $(BUILD)/bin $(SOLIB)

test-solib: $(BUILD)/test/bin $(TEST_C_OBJS)
	@LD_LIBRARY_PATH=$(BUILD)/bin:$(BUILD)/test LIBPATH=${LIBPATH} src/test/runner.py

clean:
	@rm -rf build && rm -f ${JAVA_SRC}/cipher/AES*.java
