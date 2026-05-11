.PHONY: all build run clean list

SUBDIRS := $(sort $(patsubst %/Makefile,%,$(wildcard */Makefile)))

all: build

list:
	@printf '%s\n' $(SUBDIRS)

build clean:
	@set -e; \
	for d in $(SUBDIRS); do \
		$(MAKE) -C "$$d" $@; \
	done

run:
	@fail=0; \
	for d in $(SUBDIRS); do \
		$(MAKE) -C "$$d" run || fail=1; \
	done; \
	exit $$fail
