#!/usr/bin/make -f

# Usage: (cargo build && cd tests && make)

# If the library and its development headers are installed system-wide,
# run the tests with:
#
#  (cd tests && make AS_INSTALLED=true)

SIZES = 44 65 87
FRAMES = sign signature verify public_key private_key keygen keygen_from_seed get_public_key
# Link name produced by cargo (libfips204.so / .dylib). ELF SONAME from
# build.rs is libfips204.so.0 — see RUNTIME_LIB below.
LINK_LIB = libfips204.$(SO_EXT)

OS := $(shell uname)

    CXXFLAGS += -DLINUX
ifeq ($(OS), Darwin)
    SO_EXT = dylib
else
	SO_EXT = so
endif

all: check

# adjustments for testing the local debug or release build:
ifneq ($(AS_INSTALLED),true)
SO_LOCATIONS = $(foreach w,.. ../..,$(foreach x,release debug,$w/target/$x $w/target/*/$x))
SO_LOCATION = $(dir $(firstword $(foreach d,$(SO_LOCATIONS),$(wildcard $d/$(LINK_LIB)))))

COMPILE_FLAGS = -Wl,-rpath,$(SO_LOCATION) -L $(SO_LOCATION) -I..
RUN_PREFIX = LD_LIBRARY_PATH=$(SO_LOCATION)
ifeq ($(OS), Darwin)
ADDITIONAL_RUN_DEPENDS = $(SO_LOCATION)$(LINK_LIB)
else
# cargo emits libfips204.so, but build.rs sets ELF SONAME to libfips204.so.0,
# so the loader looks for the versioned name at runtime. Create a local symlink
# for in-tree tests without changing the installed ABI layout.
ADDITIONAL_RUN_DEPENDS = $(SO_LOCATION)libfips204.so.0
$(SO_LOCATION)libfips204.so.0: $(SO_LOCATION)$(LINK_LIB)
	ln -sfn $(LINK_LIB) $@
endif
endif

BASELINES=$(foreach sz, $(SIZES), baseline-$(sz))
CHECKS=$(foreach sz, $(SIZES), runtest-$(sz))

check: $(CHECKS)

runtest-%: baseline-% $(ADDITIONAL_RUN_DEPENDS)
	$(RUN_PREFIX) ./$<

baseline-%: baseline.c ../fips204.h
	$(CC) -o $@ -g -D MLDSA_size=$* $(foreach v, $(FRAMES),-D MLDSA_$(v)=ml_dsa_$*_$(v)) -Werror -Wall -pedantic $< -Wall $(COMPILE_FLAGS) -lfips204

clean:
	rm -f $(BASELINES) $(ADDITIONAL_RUN_DEPENDS)

.PHONY: clean check all
