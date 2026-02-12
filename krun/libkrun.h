// Vendored from /usr/include/libkrun.h
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2021-2024 Red Hat, Inc.

#ifndef _LIBKRUN_H
#define _LIBKRUN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

#define KRUN_LOG_TARGET_DEFAULT -1

#define KRUN_LOG_LEVEL_OFF 0
#define KRUN_LOG_LEVEL_ERROR 1
#define KRUN_LOG_LEVEL_WARN 2
#define KRUN_LOG_LEVEL_INFO 3
#define KRUN_LOG_LEVEL_DEBUG 4
#define KRUN_LOG_LEVEL_TRACE 5

#define KRUN_LOG_STYLE_AUTO 0
#define KRUN_LOG_STYLE_ALWAYS 1
#define KRUN_LOG_STYLE_NEVER 2

#define KRUN_LOG_OPTION_NO_ENV 1

/* Disk image formats */
#define KRUN_DISK_FORMAT_RAW 0
#define KRUN_DISK_FORMAT_QCOW2 1

/* Kernel formats */
#define KRUN_KERNEL_FORMAT_RAW 0
#define KRUN_KERNEL_FORMAT_ELF 1
#define KRUN_KERNEL_FORMAT_PE_GZ 2
#define KRUN_KERNEL_FORMAT_IMAGE_BZ2 3
#define KRUN_KERNEL_FORMAT_IMAGE_GZ 4
#define KRUN_KERNEL_FORMAT_IMAGE_ZSTD 5

/**
 * Sets the log level for the library.
 */
int32_t krun_set_log_level(uint32_t level);

/**
 * Initializes logging for the library.
 */
int32_t krun_init_log(int target_fd, uint32_t level, uint32_t style, uint32_t options);

/**
 * Creates a configuration context.
 */
int32_t krun_create_ctx();

/**
 * Frees an existing configuration context.
 */
int32_t krun_free_ctx(uint32_t ctx_id);

/**
 * Sets the basic configuration parameters for the microVM.
 */
int32_t krun_set_vm_config(uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);

/**
 * Sets the path to be use as root for the microVM.
 */
int32_t krun_set_root(uint32_t ctx_id, const char *root_path);

/**
 * DEPRECATED. Use krun_add_disk instead.
 */
int32_t krun_set_root_disk(uint32_t ctx_id, const char *disk_path);

/**
 * Configures a block device to be used as root filesystem.
 * This allows booting from a block device while maintaining libkrun's built-in
 * init process through a background virtiofs mount.
 *
 * @param device: The block device path visible in the guest (e.g., "/dev/vda")
 * @param fstype: The filesystem type (e.g., "ext4")
 * @param options: Mount options (can be empty string)
 */
int32_t krun_set_root_disk_remount(uint32_t ctx_id,
                                   const char *device,
                                   const char *fstype,
                                   const char *options);

/**
 * Adds a disk image to be used as a general partition for the microVM (Raw format only).
 */
int32_t krun_add_disk(uint32_t ctx_id, const char *block_id, const char *disk_path, bool read_only);

/**
 * Adds a disk image to be used as a general partition for the microVM.
 */
int32_t krun_add_disk2(uint32_t ctx_id,
                       const char *block_id,
                       const char *disk_path,
                       uint32_t disk_format,
                       bool read_only);

/**
 * Adds an independent virtio-fs device pointing to a host's directory with a tag.
 */
int32_t krun_add_virtiofs(uint32_t ctx_id,
                          const char *c_tag,
                          const char *c_path);

/**
 * Configures a map of host to guest TCP ports for the microVM.
 */
int32_t krun_set_port_map(uint32_t ctx_id, const char *const port_map[]);

/**
 * Sets the path to the kernel to be loaded in the microVM.
 */
int32_t krun_set_kernel(uint32_t ctx_id,
                        const char *kernel_path,
                        uint32_t kernel_format,
                        const char *initramfs,
                        const char *cmdline);

/**
 * Sets environment variables to be configured in the context of the executable.
 */
int32_t krun_set_env(uint32_t ctx_id, const char *const envp[]);

/**
 * Sets the executable to be run inside the microVM.
 * exec_path: Path to the executable (relative to configured root).
 * argv: NULL-terminated array of arguments (argv[0] is typically the program name).
 * envp: NULL-terminated array of environment variables.
 */
int32_t krun_set_exec(uint32_t ctx_id,
                      const char *exec_path,
                      const char *const argv[],
                      const char *const envp[]);

/**
 * Sets the working directory for the executable.
 */
int32_t krun_set_workdir(uint32_t ctx_id, const char *workdir_path);

/**
 * Configures the console device to ignore stdin and write the output to "c_filepath".
 */
int32_t krun_set_console_output(uint32_t ctx_id, const char *c_filepath);

/**
 * Starts and enters the microVM with the configured parameters.
 * This function only returns if an error happens before starting the microVM.
 */
int32_t krun_start_enter(uint32_t ctx_id);

/* virtio-net feature flags for compatibility */
#define KRUN_NET_FEATURE_CSUM          (1 << 0)
#define KRUN_NET_FEATURE_GUEST_CSUM    (1 << 1)
#define KRUN_NET_FEATURE_GUEST_TSO4    (1 << 7)
#define KRUN_NET_FEATURE_GUEST_UFO     (1 << 10)
#define KRUN_NET_FEATURE_HOST_TSO4     (1 << 11)
#define KRUN_NET_FEATURE_HOST_UFO      (1 << 14)

#define KRUN_COMPAT_NET_FEATURES ( \
    KRUN_NET_FEATURE_CSUM | KRUN_NET_FEATURE_GUEST_CSUM | \
    KRUN_NET_FEATURE_GUEST_TSO4 | KRUN_NET_FEATURE_GUEST_UFO | \
    KRUN_NET_FEATURE_HOST_TSO4 | KRUN_NET_FEATURE_HOST_UFO)

/**
 * Adds a network device backed by a Unix stream socket.
 * Used with gvproxy's QEMU transport (4-byte BE length-prefixed frames).
 * Calling this disables TSI. krun_set_port_map returns -ENOTSUP after this.
 */
int32_t krun_add_net_unixstream(uint32_t ctx_id, const char *c_path, int fd,
                                uint8_t *const c_mac, uint32_t features,
                                uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif // _LIBKRUN_H
