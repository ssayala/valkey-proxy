POOL_CC      = gcc
POOL_CFLAGS  = -O2 -Wall -Wextra -Isrc -pthread
POOL_LDFLAGS = -pthread

# TLS support for client and backend connections (disable with: make valkey-proxy NO_TLS=1)
ifeq ($(NO_TLS),)
OPENSSL_PREFIX ?= $(shell brew --prefix openssl 2>/dev/null || echo /usr)
POOL_CFLAGS  += -DUSE_TLS -I$(OPENSSL_PREFIX)/include
POOL_LDFLAGS += -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
endif

# Sanitizer builds for testing:
#   make SANITIZE=address,undefined    memory errors, leaks, undefined behavior
#   make SANITIZE=thread               data races between threads
ifneq ($(SANITIZE),)
POOL_CFLAGS  := $(filter-out -O2,$(POOL_CFLAGS)) -O1 -g -fno-omit-frame-pointer -fsanitize=$(SANITIZE)
POOL_LDFLAGS += -fsanitize=$(SANITIZE)
endif

POOL_TARGET = valkey-proxy
POOL_SRCS   = src/valkey-proxy.c src/config.c src/cluster.c src/resp.c \
              src/pool.c src/cmd.c src/fanout.c src/pubsub.c src/acl.c src/client.c \
              src/hello.c src/event_loop.c src/mux.c src/tls.c
BUILD_DIR   = build
POOL_OBJS   = $(POOL_SRCS:%.c=$(BUILD_DIR)/%.o)

# Everything is rebuilt when the compiler flags change (switching SANITIZE=,
# NO_TLS=, ...), so objects built with different flags never get mixed.
FLAGS_STAMP := $(BUILD_DIR)/.flags
FLAGS_NOW   := $(POOL_CC) $(POOL_CFLAGS) $(POOL_LDFLAGS)
$(shell mkdir -p $(BUILD_DIR); echo '$(FLAGS_NOW)' | cmp -s - $(FLAGS_STAMP) || echo '$(FLAGS_NOW)' > $(FLAGS_STAMP))

# Print a short "CC <file>" line per step; run "make V=1" to see full commands
ifeq ($(V),1)
Q =
else
Q = @
endif

$(POOL_TARGET): $(POOL_OBJS) $(FLAGS_STAMP)
	@echo "    LINK $@"
	$(Q)$(POOL_CC) -o $@ $(POOL_OBJS) $(POOL_LDFLAGS)

# -MMD -MP tracks header dependencies, including the el_*.c files that
# event_loop.c #include's
$(BUILD_DIR)/%.o: %.c $(FLAGS_STAMP)
	@mkdir -p $(dir $@)
	@echo "    CC   $<"
	$(Q)$(POOL_CC) $(POOL_CFLAGS) -MMD -MP -c $< -o $@

-include $(POOL_OBJS:.o=.d)

# ── integration tests ────────────────────────────────────────────────────
TEST_CC     = gcc
TEST_CFLAGS = -O0 -g -Wall -Wextra -Itest -pthread

TEST_SRCS = test/run-test.c test/acl/test_acl.c test/acl/acl_fixture.c test/bitmap/test_bitmap.c \
            test/blocking/test_blocking.c \
            test/general/test_general.c test/hash/test_hash.c \
            test/geospatial/test_geospatial.c \
            test/hyperloglog/test_hyperloglog.c \
            test/list/test_list.c \
            test/pubsub/test_pubsub.c \
            test/script/test_script.c \
            test/function/test_function.c \
            test/set/test_set.c \
            test/stream/test_stream.c \
            test/string/test_string.c \
            test/zset/test_zset.c \
            test/pipeline/test_pipeline.c \
            test/txn/test_txn.c \
            test/resp3/test_resp3.c \
            test/modules/bloomfilter/test_bloomfilter.c \
            test/modules/json/test_json.c \
            test/modules/search/test_search.c

TEST_OBJS = $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)

run-test: $(TEST_OBJS)
	@echo "    LINK $@"
	$(Q)$(TEST_CC) $(TEST_CFLAGS) -o $@ $(TEST_OBJS)

$(TEST_OBJS): $(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "    CC   $<"
	$(Q)$(TEST_CC) $(TEST_CFLAGS) -MMD -MP -c $< -o $@

-include $(TEST_OBJS:.o=.d)

# Usage: make test && ./run-test -h=<host> -p=<port>
test: run-test

# ── unit tests (no server needed) ────────────────────────────────────────
# Built with the proxy's own flags and objects (SANITIZE= applies), minus
# main(): valkey-proxy.c is compiled a second time with main renamed.
UNIT_TARGET = unit-test
UNIT_OBJS   = $(filter-out $(BUILD_DIR)/src/valkey-proxy.o,$(POOL_OBJS)) \
              $(BUILD_DIR)/unit/valkey-proxy-nomain.o $(BUILD_DIR)/test/unit/test_unit.o

$(UNIT_TARGET): $(UNIT_OBJS) $(FLAGS_STAMP)
	@echo "    LINK $@"
	$(Q)$(POOL_CC) -o $@ $(UNIT_OBJS) $(POOL_LDFLAGS)

$(BUILD_DIR)/unit/valkey-proxy-nomain.o: src/valkey-proxy.c $(FLAGS_STAMP)
	@mkdir -p $(dir $@)
	@echo "    CC   $< (no main)"
	$(Q)$(POOL_CC) $(POOL_CFLAGS) -Dmain=valkey_proxy_main -MMD -MP -c $< -o $@

-include $(BUILD_DIR)/unit/valkey-proxy-nomain.d $(BUILD_DIR)/test/unit/test_unit.d

test-unit: $(UNIT_TARGET)
	./$(UNIT_TARGET)

# ── integration tests (starts its own Valkey clusters) ──────────────────
# Needs python3 and a valkey-server: $$VALKEY_SERVER, or a pinned release
# built once into test/.deps (see "Tests" in README.md).
#   make test-integration                      everything
#   make test-integration ARGS="-k failover"   only matching tests
test-integration: $(POOL_TARGET) run-test
	python3 -u test/integration/run.py $(ARGS)

test-all: test-unit test-integration

clean:
	rm -f $(POOL_TARGET) run-test $(UNIT_TARGET)
	rm -rf $(BUILD_DIR)

# ── formatting ───────────────────────────────────────────────────────────
FORMAT_SRCS = $(shell find src test -name '*.[ch]')

format:
	clang-format -i $(FORMAT_SRCS)

format-check:
	clang-format --dry-run --Werror $(FORMAT_SRCS)

.PHONY: clean test test-unit test-integration test-all format format-check

