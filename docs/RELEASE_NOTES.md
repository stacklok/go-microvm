# Release notes

## Unreleased

### Virtio-fs ownership preparation

- Added public `virtiofs.PrepareOwnership(ctx, root, relativePath, uid, gid)` for strict full-tree or targeted `user.containers.override_stat` preparation on macOS and Linux.
- Writable mounts with `OverrideUID` now use the same strict preparation before networking starts. This deliberately replaces best-effort startup behavior; failures are path-specific and abort startup.
- Read-only mounts are not prepared automatically. Explicit preparation leaves export flags and host ownership and mode unchanged. New or changed metadata still requires host xattr-write permission, so an unprivileged caller normally receives a permission error for an unannotated `0400` file.
- Existing override mode bits and `OverrideGID` defaulting are preserved. Non-opted-in and read-only mounts remain unmodified at startup, and Linux user-namespace behavior is unchanged.
- Traversal is descriptor-relative and confined beneath the authorized root: explicit symlinks fail, descendant symlinks are skipped, and malformed metadata, unsupported types, and traversal or xattr errors are fatal.
