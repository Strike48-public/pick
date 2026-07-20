/* openat2 smoke test for the freshly built proot (#248/#252).
 *
 * #248: the old proot could not translate the openat2 syscall, so libalpm's
 * pacman-DB reads failed under the sandbox. This probe opens a file via
 * openat2 (syscall 437). Run UNDER the new proot it must return a valid fd; if
 * proot cannot translate openat2 it returns an error and the CI build fails,
 * so a regression can never ship. Compiled and invoked by
 * .github/workflows/build-proot.yml.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/openat2.h>

int main(void) {
    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = O_RDONLY;

    long fd = syscall(SYS_openat2, AT_FDCWD, "/etc/hostname", &how, sizeof(how));
    if (fd < 0) {
        perror("openat2");
        return 2;
    }
    printf("openat2 ok, fd=%ld\n", fd);
    return 0;
}
