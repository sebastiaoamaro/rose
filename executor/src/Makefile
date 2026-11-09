# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../libbpf/src)
BPFTOOL_SRC := $(abspath ../../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../../blazesym/)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym.a)
LIBBLAZESYM_HEADER := $(abspath $(OUTPUT)/blazesym.h)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../../vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall -Wextra
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = uprobes tc aux fault_schedule fault_inject
MAIN = executor
TCMAIN = network_manager
INJECTMAIN = rose_inject_helper

CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS :=
APPS += $(BZS_APPS)
# Required by libblazesym
ALL_LDFLAGS += -lrt -ldl -lpthread -lm -Wall
endif

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/uprobe_helpers.o \
	$(OUTPUT)/btf_helpers.o \

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)


.PHONY: all ROSE TC INJECT
all: $(APPS) ROSE TC INJECT
ROSE: $(MAIN)
TC: $(TCMAIN)
INJECT: $(INJECTMAIN)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)
	$(Q)rm -f executor/executor
	$(Q)rm -f network_manager/network_manager
	$(Q)rm -f inject/rose_inject_helper

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap


$(LIBBLAZESYM_SRC)/target/release/libblazesym.a::
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --features=cheader,dont-generate-test-files --release

$(LIBBLAZESYM_OBJ): $(LIBBLAZESYM_SRC)/target/release/libblazesym.a | $(OUTPUT)
	$(call msg,LIB, $@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/libblazesym.a $@

$(LIBBLAZESYM_HEADER): $(LIBBLAZESYM_SRC)/target/release/libblazesym.a | $(OUTPUT)
	$(call msg,LIB,$@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/blazesym.h $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard *.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		     -c -w $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o *.h | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@


# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(call msg,CC,$^)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(patsubst %,$(OUTPUT)/%.o,$(BZS_APPS)): $(LIBBLAZESYM_HEADER)

$(BZS_APPS): $(LIBBLAZESYM_OBJ)

OFILES=$(patsubst %,$(OUTPUT)/%.o,$(APPS))

# App modules have no main(); build their .o files and mark done with a stamp
$(APPS): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,APP,$@)
	$(Q)touch $@

# Build executor binary
$(MAIN): %: executor/executor.c $(LIBBPF_OBJ) $(APPS)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -I .output/ -I . -c executor/executor.c -o .output/executor.o
	$(Q)$(CC) $(CFLAGS) .output/executor.o $(ALL_LDFLAGS) $(OFILES) $(COMMON_OBJ) $(LIBBPF_OBJ) -lelf -lz -o executor/executor

# Build network_manager binary
$(TCMAIN): %: network_manager/network_manager.c $(LIBBPF_OBJ) $(APPS)
	$(call msg,TC BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -I .output/ -I . -c network_manager/network_manager.c -o .output/network_manager.o
	$(Q)$(CC) $(CFLAGS) .output/network_manager.o $(ALL_LDFLAGS) $(OFILES) $(COMMON_OBJ) $(LIBBPF_OBJ) -lelf -lz -o network_manager/network_manager

# Build rose_inject_helper binary - the one compiled piece dynamic fault
# injection needs (attaching a brand-new uprobe / dumping struct layout
# for schedule_parser/rose_injector.py). Links against the same $(APPS)
# object files as `executor`, in particular uprobes.o for uprobe() itself.
$(INJECTMAIN): %: inject/rose_inject_helper.c $(LIBBPF_OBJ) $(APPS)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -I .output/ -I . -c inject/rose_inject_helper.c -o .output/rose_inject_helper.o
	$(Q)$(CC) $(CFLAGS) .output/rose_inject_helper.o $(ALL_LDFLAGS) $(OFILES) $(COMMON_OBJ) $(LIBBPF_OBJ) -lelf -lz -o inject/rose_inject_helper


# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
