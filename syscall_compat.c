/* syscall_compat.c — LD_PRELOAD shim for proot on Android.
 *
 * Android's Zygote-inherited seccomp filter blocks old-style syscalls
 * (dup2, access, pipe) with SIGSYS on newer API levels. glibc inside
 * the proot rootfs still uses these, causing "Function not implemented".
 *
 * This library overrides the glibc wrappers to use the newer syscall
 * equivalents that Android allows through its seccomp filter.
 *
 * NOTE: Do NOT override flock() here. The Termux-patched proot already
 * handles SYS_flock → SYS_fcntl translation at the ptrace/syscall level.
 * Overriding at the library level bypasses proot's fd translation and
 * breaks pacman's database locking.
 *
 * Built by: just build-syscall-compat
 * Used via: LD_PRELOAD=/usr/local/lib/syscall_compat.so inside proot
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* dup2(old, new) → dup3(old, new, 0)
 * Android blocks syscall 33 (dup2) but allows 292 (dup3) on x86_64. */
int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) {
        /* dup2 spec: if equal, just validate oldfd */
        if (fcntl(oldfd, F_GETFD) == -1) return -1;
        return oldfd;
    }
    return syscall(SYS_dup3, oldfd, newfd, 0);
}

/* access(path, mode) → faccessat(AT_FDCWD, path, mode, 0)
 * Android blocks syscall 21 (access) but allows faccessat. */
int access(const char *pathname, int mode) {
    return syscall(SYS_faccessat, AT_FDCWD, pathname, mode, 0);
}

/* pipe(fds) → pipe2(fds, 0)
 * Android blocks syscall 22 (pipe) but allows pipe2. */
int pipe(int pipefd[2]) {
    return syscall(SYS_pipe2, pipefd, 0);
}
