# SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#
# Copy Fail -- CVE-2026-31431
# AF_ALG + splice() page-cache-mutation LPE proof-of-concept.
# Disclosed 2026-04-29 by Theori / Xint. Writeup: https://copy.fail/
#
# Build flow:
#   payload.c -> payload         ($(CC), nolibc, freestanding, static)
#   payload   -> payload.o       ($(LD) -r -b binary, raw bytes -> .o)
#   exploit.c + payload.o -> exploit
#
# `ld -r -b binary` synthesizes three symbols in payload.o, mangling the
# input filename: _binary_payload_start, _binary_payload_end, _binary_payload_size.
# exploit.c declares the first two as extern and gets the bytes for free
# at link time.
#
# Toolchain knobs:
#   CC     compiler for both    (default: cc)
#   LD     linker for embed     (default: ld)
#
# For cross-compilation, point both at the cross toolchain:
#     make CC=aarch64-linux-gnu-gcc LD=aarch64-linux-gnu-ld
#
# nolibc.h handles per-arch syscall asm internally. Supported arches:
# x86_64, i386, arm, aarch64, riscv32/64, mips, ppc, s390x, loongarch,
# m68k, sh, sparc.

CC ?= cc
LD ?= ld

CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?= -Wl,-z,noexecstack

# nolibc / freestanding payload build:
#   -nostdlib                       no glibc/musl init or libs
#   -static                         no dynamic linker
#   -ffreestanding                  no hosted-environment assumptions
#   -fno-asynchronous-unwind-tables drop .eh_frame
#   -fno-ident                      drop .comment section
#   -fno-stack-protector            we have no __stack_chk_fail
#   -Os -s                          size-opt + strip
#   -Inolibc                        find nolibc.h
#
# Linker flags:
#   -Wl,-N                          merge text+data into one RWX LOAD segment
#                                   (saves ~10 KB of page-alignment padding;
#                                   produces a "RWX permissions" warning that
#                                   is informational only, not a runtime issue)
#   -Wl,-z,max-page-size=0x10       tell ld page alignment is 16 bytes -- pure
#                                   on-disk packing, kernel still uses 4 KB
#                                   pages at runtime
PAYLOAD_BASE_CFLAGS ?= -nostdlib -static -Os -s \
                       -ffreestanding \
                       -fno-asynchronous-unwind-tables \
                       -fno-ident \
                       -fno-stack-protector \
                       -Inolibc
PAYLOAD_PACK_LDFLAGS ?= -Wl,-N -Wl,-z,max-page-size=0x10
PAYLOAD_CFLAGS ?= $(PAYLOAD_BASE_CFLAGS) $(PAYLOAD_PACK_LDFLAGS)

.PHONY: all clean info musl-shim musl-static zig-musl-static FORCE

all: exploit exploit-passwd vulnerable

# musl-static: tiny (~55 KB exploit + ~1.5 KB payload), no glibc dependency.
# Requires musl-tools and linux-libc-dev. musl-gcc isolates its include path
# and doesn't expose kernel UAPI headers, so we shim them via symlink.
ARCH := $(shell uname -m)
MUSL_SHIM_DIR ?= .musl-shim
UAPI_LINUX_DIR ?= /usr/include/linux
UAPI_ASM_GENERIC_DIR ?= /usr/include/asm-generic
UAPI_ASM_DIR ?= /usr/include/$(ARCH)-linux-gnu/asm
musl-shim:
	@test -d "$(UAPI_LINUX_DIR)" || { echo "missing UAPI headers: $(UAPI_LINUX_DIR)" >&2; exit 1; }
	@test -d "$(UAPI_ASM_GENERIC_DIR)" || { echo "missing UAPI headers: $(UAPI_ASM_GENERIC_DIR)" >&2; exit 1; }
	@test -d "$(UAPI_ASM_DIR)" || { echo "missing UAPI headers: $(UAPI_ASM_DIR)" >&2; exit 1; }
	@mkdir -p "$(MUSL_SHIM_DIR)"
	@ln -sfn "$(UAPI_LINUX_DIR)" "$(MUSL_SHIM_DIR)/linux"
	@ln -sfn "$(UAPI_ASM_GENERIC_DIR)" "$(MUSL_SHIM_DIR)/asm-generic"
	@ln -sfn "$(UAPI_ASM_DIR)" "$(MUSL_SHIM_DIR)/asm"

musl-static: musl-shim
	$(MAKE) CC=musl-gcc \
	    PAYLOAD_CFLAGS="$(PAYLOAD_CFLAGS) -isystem $(CURDIR)/$(MUSL_SHIM_DIR)" \
	    CFLAGS="$(CFLAGS) -isystem $(CURDIR)/$(MUSL_SHIM_DIR)"

# Empty: zig cc rejects -Wl,-N, so we use lld's default page-size alignment.
ZIG_PAYLOAD_PACK_LDFLAGS ?=
ZIG_CC ?= zig cc

# An empty .c file compiled with zig's target gives `ld -r -b binary` an
# ABI-aware donor object so payload.o keeps target-specific e_flags
# (e.g. RISC-V's float-ABI bits).
zig-musl-static: musl-shim
	@test -n "$(ZIG_TARGET)" || { echo "ZIG_TARGET is required, e.g. x86_64-linux-musl" >&2; exit 1; }
	$(MAKE) CC="$(ZIG_CC) -target $(ZIG_TARGET)" \
	    LD="$(LD)" \
	    PAYLOAD_OBJ_DEPS="payload-abi.o" \
	    PAYLOAD_ABI_OBJ_CMD="$(ZIG_CC) -target $(ZIG_TARGET) -x c -c /dev/null -o payload-abi.o" \
	    PAYLOAD_OBJ_CMD="$(LD) -r -z noexecstack -o payload.o payload-abi.o -b binary payload" \
	    PAYLOAD_CFLAGS="$(PAYLOAD_BASE_CFLAGS) $(ZIG_PAYLOAD_PACK_LDFLAGS) -isystem $(CURDIR)/$(MUSL_SHIM_DIR)" \
	    CFLAGS="$(CFLAGS) -isystem $(CURDIR)/$(MUSL_SHIM_DIR)"

payload: payload.c
	$(CC) $(PAYLOAD_CFLAGS) $< -o $@

# Default embed path: the synthesized symbol names are derived from the input
# filename as given on the command line. We pass `payload` (not `./payload`),
# so the symbols are _binary_payload_start etc., not _binary___payload_start.
PAYLOAD_OBJ_DEPS ?=
PAYLOAD_OBJ_CMD ?= $(LD) -r -b binary -o $@ $<
PAYLOAD_ABI_OBJ_CMD ?= @echo "PAYLOAD_ABI_OBJ_CMD is required" >&2; exit 1
payload.o: payload $(PAYLOAD_OBJ_DEPS)
	$(PAYLOAD_OBJ_CMD)

payload-abi.o: FORCE
	$(PAYLOAD_ABI_OBJ_CMD)

# Shared AF_ALG/splice page-cache mutation primitive. Linked into all three
# binaries; declaration in utils.h, definition in utils.c.
utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c $< -o $@

exploit: exploit.c utils.o payload.o
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $^

# Non-destructive vulnerability checker. Mutates a local testfile's page
# cache and reads it back to detect kernel susceptibility without touching
# any system file.
vulnerable: vulnerable.c utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $^

# /etc/passwd UID-flip variant. No payload needed; mutates four ASCII bytes
# of /etc/passwd's page cache to flip the user's UID to "0000", then execs su.
exploit-passwd: exploit-passwd.c utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $^

info: payload payload.o
	@echo "=== payload size ==="
	@stat -c '%n: %s bytes' payload
	@SZ=$$(stat -c '%s' payload); echo "  -> $$(( (SZ + 3) / 4 )) patch_chunk iterations"
	@echo
	@echo "=== payload.o symbols ==="
	@nm payload.o
	@echo
	@echo "=== payload sections ==="
	@readelf -S payload | grep -E 'Name|\.text|\.rodata|\.data|\.bss' | head -10

clean:
	rm -rf exploit vulnerable exploit-passwd payload payload.o payload-abi.o utils.o testfile .musl-shim
