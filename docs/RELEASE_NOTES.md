# Release notes

## Unreleased

### Virtio-fs ownership preparation

- Added public `virtiofs.PrepareOwnership(ctx, root, relativePath, uid, gid)` for strict full-tree or targeted `user.containers.override_stat` preparation on macOS and Linux.
- Mounts with `OverrideUID`, including read-only exports, prepare ownership before networking. Startup is best-effort by default: recoverable entry failures produce one bounded incomplete-mount warning while safe descendants, siblings, later mounts, and startup continue.
- Added per-mount `StrictOwnershipPreparation` to abort before networking and VM startup on the first preparation failure. The public API remains strict, and cancellation or mount root/target acquisition failures always abort.
- Both policies share descriptor-relative, `O_NOFOLLOW` traversal. Explicit symlinks fail, descendant symlinks are skipped, and host ownership, mode, and export flags are unchanged.
- Existing override mode bits and `OverrideGID` defaulting are preserved. Mounts without `OverrideUID` remain unmodified, and Linux user-namespace behavior is unchanged. New or changed metadata still requires host xattr-write permission; matching metadata is not rewritten.
