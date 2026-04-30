# Copy Fail (CVE-2026-31431) - C port

A cross-platform C reimplementation of the Copy Fail Linux LPE (CVE-2026-31431),
disclosed 2026-04-29 by Theori / Xint. See the canonical writeup at
[copy.fail](https://copy.fail/) for the full vulnerability description, timeline,
and Theori's discovery process.

The publicly-released proof-of-concept is a 732-byte Python script. This C port
demonstrates that the same exploit can be expressed as portable C compilable to
any architecture nolibc supports, with no per-arch hex blobs or inline assembly
in the project's own source.

Author of this port: Tony Gies <tony.gies@crashunited.com>.
Discovery and original disclosure: Theori / Xint.

## Repository layout

```
copy-fail-c/
├── exploit.c           the dropper (AF_ALG + splice page-cache mutation)
├── payload.c           the body that gets dropped (setgid+setuid+execve sh)
├── Makefile            build orchestration
├── nolibc/             vendored from torvalds/linux tools/include/nolibc
└── README.md           this file
```

After `make`:

```
├── payload             tiny static ELF, embedded into the dropper as bytes
├── payload.o           payload wrapped as a relocatable .o by `ld -r -b binary`
└── exploit             final dropper binary
```

`exploit.c` opens the target binary read-only, then for each 4-byte window of
the embedded payload runs one bogus AEAD-decrypt through AF_ALG whose
ciphertext input is supplied via splice() from the target's page-cache pages.
The authencesn template's in-place optimization treats the splice'd source
pages as both the ciphertext input and the plaintext destination, so the
(failing) decrypt has already overwritten the page-cache page by the time
authentication verification rejects the request. After 4 * N iterations the
target's cached image has been replaced byte-for-byte with the payload.
execve()'ing the target loads the mutated pages; the on-disk inode is still
setuid root, so the kernel grants root credentials and runs the payload.

`payload.c` is plain portable C: `setgid(0); setuid(0); execve("/bin/sh",
...)`. nolibc supplies the `_start`, the syscall machinery, and the per-arch
register-juggling.


## Build

Default (host-arch native):

```sh
make
```

Cross-compile to aarch64 (or any other Linux arch a cross-toolchain is
installed for):

```sh
make CC=aarch64-linux-gnu-gcc LD=aarch64-linux-gnu-ld
```

Architectures supported by the vendored nolibc (per upstream): x86_64, i386,
arm, aarch64, riscv32/64, mips, ppc, s390x, loongarch, m68k, sh, sparc.
nolibc dispatches on the compiler's arch macros, so picking the right
`CC`/`LD` is sufficient.

Required to build:

* a C compiler (`cc`, `gcc`, or any cross variant)
* a linker that supports `ld -r -b binary` (binutils ld and lld both do)
* kernel UAPI headers providing `linux/if_alg.h` and `<asm/unistd.h>`
  (Debian/Ubuntu: `linux-libc-dev`; cross variants: typically pulled in by
  the cross-toolchain package)

There are no external library dependencies. The payload is built freestanding
against nolibc; the dropper links against the host libc only for `fprintf`
and `perror`.


## Architectural choices

Three small toolchain features carry most of the weight in keeping the source
portable and the payload small.

### nolibc

`nolibc/` is the kernel's tiny header-only libc replacement, vendored from
torvalds/linux `tools/include/nolibc/`. It provides `_start`, a portable
`syscall()` macro, and inline syscall wrappers, with the per-arch register
conventions encoded in `nolibc/arch-*.h`. Building the payload with
`-nostdlib -static -ffreestanding -Inolibc` produces a tiny static ELF that
calls into the kernel directly without dragging in glibc startup, TLS init,
or stack-canary plumbing. Result: ~1.7 KB on x86_64, ~2.0 KB on aarch64,
versus ~17 KB for the same `payload.c` linked against musl-static or
~700 KB against glibc-static.

### `ld -r -b binary` for embedding

The Makefile turns the built `payload` ELF into `payload.o` via `ld -r -b
binary -o payload.o payload`. The linker emits the input bytes verbatim as
the data section of a relocatable object file and synthesizes three symbols
from the input filename:

```
_binary_payload_start    address of first payload byte
_binary_payload_end      address one past the last payload byte
_binary_payload_size     absolute symbol whose value is the size in bytes
```

`exploit.c` declares the first two as `extern const unsigned char[]` and
computes the size as `_binary_payload_end - _binary_payload_start`. There is
no `xxd -i`-generated header file, no embedded array literal, no source
regeneration step. The payload bytes pass through the build as a real
linker artifact.

### `-Wl,-N` plus tight `max-page-size`

The payload is statically linked with `-Wl,-N -Wl,-z,max-page-size=0x10`,
which collapses `.text`/`.rodata`/`.data` into a single LOAD segment with
16-byte file-alignment instead of the kernel-page-aligned 4 KB-per-segment
default. This produces an "RWX permissions" warning from `ld`, which is
informational only - the payload's runtime memory protection doesn't matter
to its single-purpose program. Without this flag, the same code links to ~13
KB on x86_64 (mostly inter-segment zero padding); with it, ~1.7 KB.


## Affected kernels

```
floor:    torvalds/linux 72548b093ee3   August 2017, v4.14
                                        (AF_ALG iov_iter rework that
                                         introduced the file-page write
                                         primitive via splice into the AEAD
                                         scatterlist)

ceiling:  torvalds/linux a664bf3d603d   April 2026, mainline
                                        (reverts the 2017 algif_aead
                                         in-place optimization; separates
                                         source and destination scatterlists
                                         so page-cache pages can no longer
                                         be a writable crypto destination)
```

In between: every major distro kernel that didn't backport the fix.
Ubuntu, RHEL, SUSE, Amazon Linux, and Debian were all confirmed vulnerable
in their stock cloud-image kernels at disclosure time. Distro-level
backports started rolling out around 2026-04-29 alongside the public
disclosure. To verify whether a target kernel is in-window, check whether
`a664bf3d603d` (or its distro-specific backport) is present in the kernel's
git log or the distro's changelog.


## Verification

Local cross-arch sanity check via qemu-user-static:

```sh
sudo apt install qemu-user-static gcc-aarch64-linux-gnu binfmt-support
make clean
make CC=aarch64-linux-gnu-gcc LD=aarch64-linux-gnu-ld
file payload                         # ELF 64-bit LSB executable, ARM aarch64
echo 'id; exit' | ./payload          # runs via binfmt_misc -> qemu-aarch64-static
```

This confirms the per-arch syscall asm in `nolibc/arch-arm64.h` dispatches
correctly and that the build pipeline cross-compiles cleanly. It does not
exercise the kernel-side AF_ALG/splice primitive on an aarch64 kernel,
because qemu-user-static forwards syscalls to the host kernel. For full
kernel-level verification on a foreign arch, use `qemu-system-aarch64` with
a vulnerable cloud image, or a real aarch64 host.


## License and credits

Discovery and original disclosure of CVE-2026-31431: Theori / Xint.
Public writeup: <https://copy.fail/>.

This C port: Tony Gies <tony.gies@crashunited.com>

`nolibc/`: vendored from the Linux kernel tree, dual-licensed
LGPL-2.1-or-later OR MIT (see `nolibc/nolibc.h` and individual file
SPDX headers).

The dropper and payload sources in this repository are released under the
same dual LGPL-2.1-or-later OR MIT terms as the nolibc tree they depend on,
to keep the licensing trivially compatible for anyone vendoring this whole
directory into their own work.

The exploit and payload are published for security-research and
defensive-detection purposes. Use against systems you do not own or have
explicit authorization to test is your problem, not the author's.
