CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
CPPFLAGS ?=
LDFLAGS ?=

TEST_SRCS := $(sort $(wildcard *.c))
TEST_BINS := $(TEST_SRCS:.c=)

.PHONY: all build run clean list

all: build

list:
	@printf '%s\n' $(TEST_BINS)

build: $(TEST_BINS)

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -I ../../include -L ../../lib -o $@ $< $(LDFLAGS) -lpseudo

run: build
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "==> $$t"; \
		./$$t || { rc=$$?; echo "FAIL: $$t (exit $$rc)"; fail=1; }; \
	done; \
	exit $$fail

clean:
	rm -f $(TEST_BINS)
