/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Copy Fail -- CVE-2026-31431
 * Vulnerability checker.
 *
 * Detects whether the running kernel is susceptible to the AF_ALG/splice
 * page-cache mutation primitive used by exploit.c and exploit-passwd.c,
 * without touching any system file. Creates a local "testfile" in the
 * working directory containing the string "init", then runs the same
 * patch_chunk() primitive against its page cache to attempt to overwrite
 * the bytes with "vulnerable". Reads back to confirm whether the
 * mutation took.
 *
 * The on-disk inode is never modified; the testfile is removed on exit,
 * and the page-cache mutation evaporates with it. Runs unprivileged.
 *
 * Exits 100 if the kernel is vulnerable, 0 otherwise.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include "utils.h"

static const char PAYLOAD[] = "vulnerable";
#define PAYLOAD_LEN (sizeof PAYLOAD - 1)

static int check_file(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return 0;
    printf("content of %s fd=%d ---\n", filename, fd);
    char buf[256];
    ssize_t total = read(fd, buf, sizeof buf);
    if (total > 0)
        write(STDOUT_FILENO, buf, total);
    close(fd);
    printf("\n---\n");
    return total >= (ssize_t)PAYLOAD_LEN &&
           memcmp(buf, PAYLOAD, PAYLOAD_LEN) == 0;
}

static void init_file(const char *filename) {
    static const char init_buf[32] = "init";
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", filename, strerror(errno));
        exit(1);
    }
    write(fd, init_buf, sizeof init_buf);
    close(fd);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    const char *target = "testfile";

    init_file(target);
    sync();
    check_file(target);

    int file_fd = open(target, O_RDONLY);
    if (file_fd < 0) {
        fprintf(stderr, "open(%s): %s\n", target, strerror(errno));
        unlink(target);
        return 1;
    }

    size_t iters = (PAYLOAD_LEN + 3) / 4;

    fprintf(stderr, "[+] target:    %s\n", target);
    fprintf(stderr, "[+] payload:   %zu bytes (%zu iterations)\n",
            PAYLOAD_LEN, iters);

    /* Walk the payload in 4-byte windows. window[] is 5 bytes so the
     * trailing zero acts as a NUL terminator for the %s log below. */
    for (off_t off = 0; (size_t)off < PAYLOAD_LEN; off += 4) {
        unsigned char window[5] = { 0, 0, 0, 0, 0 };
        size_t take = (PAYLOAD_LEN - (size_t)off >= 4)
                      ? 4 : PAYLOAD_LEN - (size_t)off;
        memcpy(window, PAYLOAD + off, take);

        fprintf(stderr, "[+] patch fd=%d off=%lld bytes=\"%s\"\n",
                file_fd, (long long)off, window);
        if (patch_chunk(file_fd, off, window) < 0) {
            int ret = 1;
            if (errno == EAFNOSUPPORT) {
                fprintf(stderr, "[+] AF_ALG module not available; not vulnerable\n");
                ret = 0;
            }
            else if (errno == ENOENT) {
                fprintf(stderr, "[+] AF_ALG aead algorithm not available; not vulnerable\n");
                ret = 0;
            }
            else {
                fprintf(stderr, "[-] patch_chunk failed at offset %lld\n",
                    (long long)off);
                ret = 1;
            }

            close(file_fd);
            unlink(target);
            return ret;
        }
        fprintf(stderr, "[+] patch ok\n");
    }

    close(file_fd);

    fprintf(stderr, "[+] page cache mutated\n");

    int vulnerable = check_file(target);
    unlink(target);

    if (vulnerable) {
        fprintf(stderr, "[!] VULNERABLE\n");
        return 100;
    }

    fprintf(stderr, "[+] not vulnerable :)\n");
    return 0;
}
