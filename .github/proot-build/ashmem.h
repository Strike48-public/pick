/* Minimal linux/ashmem.h stub for building termux/proot on glibc/Debian.
 *
 * termux/proot's Android-only `ashmem_memfd` extension #includes
 * <linux/ashmem.h>, which does not exist in mainline glibc headers. We stub it
 * (rather than delete the object) because cli/proot.c references
 * ashmem_memfd_callback. See .github/workflows/build-proot.yml and #248/#252.
 */
#ifndef _LINUX_ASHMEM_H
#define _LINUX_ASHMEM_H

#include <linux/limits.h>
#include <linux/ioctl.h>

#define ASHMEM_NAME_LEN 256
#define ASHMEM_NAME_DEF "dev/ashmem"

#define ASHMEM_SET_NAME _IOW(0x77, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE _IOW(0x77, 3, size_t)

#endif /* _LINUX_ASHMEM_H */
