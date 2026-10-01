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

# C HashML-DSA tests need libmd. But Ubuntu 24.04 libmd-dev does not ship sha3.h,
# and libmd < 1.3.0 didn't have SHA2-512/224 either.
# HashML-DSA is covered for more digest algorithms by ffi/python/test/nist.py.
LIBMD_CFLAGS := $(shell pkgconf --cflags libmd 2>/dev/null || true)
LIBMD_LIBS := $(shell pkgconf --libs libmd 2>/dev/null || true)
HAS_LIBMD = No
ifneq ($(LIBMD_LIBS),)
  COMPILE_FLAGS += $(LIBMD_CFLAGS) $(LIBMD_LIBS) -DHAVE_LIBMD
  FRAMES += hash_sign hash_verify
  HAS_LIBMD = Yes
  # -include avoids a '#' in this Makefile (which would start a comment).
  HAS_SHA3_H := $(shell $(CC) $(LIBMD_CFLAGS) -E -include sha3.h -x c /dev/null -o /dev/null 2>/dev/null && echo yes)
ifeq ($(HAS_SHA3_H),yes)
  COMPILE_FLAGS += -DHAVE_SHA3
  HAS_LIBMD += +SHA3
endif
endif


BASELINES=$(foreach sz, $(SIZES), baseline-$(sz))
CHECKS=$(foreach sz, $(SIZES), run-baseline-$(sz)) run-nist-tests run-link-two run-cplusplus

check: status $(CHECKS)

status:
	printf "With libmd: %s\n" "$(HAS_LIBMD)"

run-%: % $(ADDITIONAL_RUN_DEPENDS)
	$(RUN_PREFIX) ./$<

baseline-%: baseline.c ../fips204.h
	$(CC) -o $@ -g -D MLDSA_size=$* $(foreach v, $(FRAMES),-D MLDSA_$(v)=ml_dsa_$*_$(v)) -Werror -Wall -pedantic $< -Wall $(COMPILE_FLAGS) -lfips204

nist-tests.c:  nist-tests-template.c generate-nist.py
	./generate-nist.py > $@.tmp
	mv $@.tmp $@

nist-tests: nist-tests.c ../fips204.h
	$(CC) -o $@ -g  -Werror -Wall -pedantic $< -Wall $(COMPILE_FLAGS) -lfips204

# Two translation units that both include fips204.h must link.
link-two: two_a.c two_b.c ../fips204.h
	$(CC) -o $@ -g -Werror -Wall -pedantic two_a.c two_b.c $(COMPILE_FLAGS) -lfips204

# fips204.h must also compile and link as C++ (C++11 is the oldest supported).
cplusplus: cplusplus.cc ../fips204.h
	$(CXX) -o $@ -g -std=c++11 -Werror -Wall -Wextra -pedantic $< $(COMPILE_FLAGS) -lfips204

clean:
	rm -f $(BASELINES) $(ADDITIONAL_RUN_DEPENDS) nist-tests.c nist-tests link-two cplusplus

.PHONY: clean check all
