JAVA_HOME := /usr/lib/jvm/java-21-openjdk-amd64/
BUILD     := ${PWD}/build

# Vars for compiling Java sources
JAVA_SRC      := src/java/com/canonical/openssl
JAVA_SRC_DIRS := ${JAVA_SRC} ${JAVA_SRC}/drbg ${JAVA_SRC}/keyagreement ${JAVA_SRC}/keyencapsulation ${JAVA_SRC}/mac
JAVA_SRC_DIRS += ${JAVA_SRC}/kdf ${JAVA_SRC}/md ${JAVA_SRC}/signature ${JAVA_SRC}/key ${JAVA_SRC}/cipher
JAVA_SRC_DIRS += ${JAVA_SRC}/provider ${JAVA_SRC}/util
JAVA_FILES    := $(wildcard $(addsuffix /*.java, $(JAVA_SRC_DIRS)))

# Vars for compiling the C sources
JSSL_HEADERS    := -I${PWD}/src/include/jni -I${PWD}/src/include/native
JNI_HEADERS     := -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/
OPENSSL_HEADERS := -I/usr/local/include/openssl/
INCLUDE_HEADERS := ${JSSL_HEADERS} ${JNI_HEADERS} ${OPENSSL_HEADERS}

NATDIR   := ${PWD}/src/native
NATFILES := $(foreach dir,$(NATDIR),$(wildcard $(dir)/*.c))
NATOBJS  := $(patsubst $(NATDIR)/%.c, $(BUILD)/bin/%.o, $(NATFILES))

JNIDIR   := ${PWD}/src/jni
JNIFILES := $(foreach dir,$(JNIDIR),$(wildcard $(dir)/*.c))
JNIOBJS  := $(patsubst $(JNIDIR)/%.c, $(BUILD)/bin/%.o, $(JNIFILES))
OBJS     := $(NATOBJS) $(JNIOBJS)

CCFLAGS := ${INCLUDE_HEADERS} -c -fPIC
LDFLAGS := -shared -fPIC -Wl,-soname,libjssl.so
SOLIB   := $(BUILD)/bin/libjssl.so

# Vars for compiling the test sources
TEST_BIN := ${PWD}/build/test/bin
TEST_C_DIR := ${PWD}/test/native
TEST_C_SRCS := $(foreach dir,$(TEST_C_DIR),$(wildcard $(dir)/*.c))
TEST_C_OBJS := $(patsubst $(TEST_C_DIR)/%.c,$(TEST_BIN)/%,$(TEST_C_SRCS))
TEST_CFLAGS := ${INCLUDE_HEADERS} -L${BUILD}/bin -L/usr/local/lib64
TEST_JAVA_DIR := ${PWD}/test/java
TEST_JAVA_SRCS := $(wildcard $(addsuffix /*.java, $(TEST_JAVA_DIR)))
TEST_NAT_SRCS := $(wildcard $(addsuffix /*.c, $(TEST_JAVA_DIR)/native))
TESTOBJS      := $(patsubst $(TEST_JAVA_DIR)/native/%.c, $(TEST_BIN)/%.o, $(TEST_NAT_SRCS))
TESTLIB := $(BUILD)/test/bin/libsigtest.so

LIBPATH := $(BUILD)/bin:${PWD}/build/test/bin

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

$(TESTLIB): $(TESTOBJS)
	@cc -shared -fPIC -Wl,-soname,libsigtest.so -o $@ $^ -L/usr/local/lib64 -L$(BUILD)/bin -lcrypto -lssl -ljssl

$(TEST_BIN)/%: $(TEST_C_DIR)/%.c
	@cc $(TEST_CFLAGS) -o $@ $< -ljssl -lcrypto

gen-code:
	@sh ${PWD}/gen/gen-classes.sh

java-build: $(BUILD)/classes $(JAVA_FILES)
	@${JAVA_HOME}/bin/javac -d $^

build: $(BUILD)/bin $(SOLIB) gen-code java-build
	@cp ${SOLIB} $(BUILD)/classes/resources/native

build-test: $(TEST_JAVA_SRCS) $(BUILD)/test/bin $(TESTLIB) $(TEST_C_OBJS)
	@${JAVA_HOME}/bin/javac -cp build/classes -d build/test/classes $(TEST_JAVA_SRCS)

test: build build-test
	@LD_LIBRARY_PATH=$(BUILD)/bin:$(BUILD)/test JAVA_HOME=${JAVA_HOME} LIBPATH=${LIBPATH} test/runner.py

clean:
	@rm -rf build && rm -f ${JAVA_SRC}/cipher/AES*.java
