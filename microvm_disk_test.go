// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package microvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/image"
	"github.com/stacklok/go-microvm/preflight"
)

func TestWithDisks_AppendsInOrder(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Empty(t, cfg.disks)

	WithDisks(Disk{ID: "data", HostPath: "/var/lib/vm/data.img"}).apply(cfg)
	WithDisks(Disk{ID: "seed", HostPath: "/var/lib/vm/seed.qcow2", Format: DiskFormatQCOW2, ReadOnly: true}).apply(cfg)

	require.Len(t, cfg.disks, 2)
	assert.Equal(t, "data", cfg.disks[0].ID)
	assert.Equal(t, "seed", cfg.disks[1].ID)
	assert.Equal(t, DiskFormatQCOW2, cfg.disks[1].Format)
	assert.True(t, cfg.disks[1].ReadOnly)
}

func TestValidateDisks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	image := filepath.Join(dir, "data.img")
	require.NoError(t, os.WriteFile(image, nil, 0o600))

	tests := []struct {
		name    string
		disks   []Disk
		wantErr string
	}{
		{name: "no disks"},
		{name: "raw default", disks: []Disk{{ID: "data", HostPath: image}}},
		{name: "qcow2 read-only", disks: []Disk{{ID: "seed", HostPath: image, Format: DiskFormatQCOW2, ReadOnly: true}}},
		{name: "empty ID", disks: []Disk{{HostPath: image}}, wantErr: "ID must not be empty"},
		{name: "duplicate ID", disks: []Disk{{ID: "a", HostPath: image}, {ID: "a", HostPath: image}}, wantErr: "duplicate ID"},
		{name: "unknown format", disks: []Disk{{ID: "a", HostPath: image, Format: "vmdk"}}, wantErr: "unsupported format"},
		{name: "relative path", disks: []Disk{{ID: "a", HostPath: "data.img"}}, wantErr: "must be absolute"},
		{name: "missing file", disks: []Disk{{ID: "a", HostPath: filepath.Join(dir, "missing.img")}}, wantErr: "no such file"},
		{name: "directory", disks: []Disk{{ID: "a", HostPath: dir}}, wantErr: "not a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			WithDisks(tt.disks...).apply(cfg)
			err := validateDisks(cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRun_RejectsInvalidDiskBeforeStart(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), "alpine:latest",
		WithDataDir(t.TempDir()),
		WithDisks(Disk{ID: "data", HostPath: "relative.img"}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be absolute")
}

func TestRun_InvalidDiskPreservesData(t *testing.T) {
	t.Parallel()

	for _, problem := range []string{"ID", "duplicate", "format", "relative", "missing", "directory"} {
		t.Run(problem, func(t *testing.T) {
			t.Parallel()
			dataDir := t.TempDir()
			diskPath := filepath.Join(dataDir, "data.img")
			statePath := filepath.Join(dataDir, "go-microvm-state.json")
			require.NoError(t, os.WriteFile(diskPath, []byte("disk contents"), 0o600))
			state := []byte(`{"version":1,"active":true,"pid":1234}`)
			require.NoError(t, os.WriteFile(statePath, state, 0o600))

			disks := []Disk{{ID: "data", HostPath: diskPath}}
			switch problem {
			case "ID":
				disks[0].ID = ""
			case "duplicate":
				disks = append(disks, disks[0])
			case "format":
				disks[0].Format = "vmdk"
			case "relative":
				disks[0].HostPath = "relative.img"
			case "missing":
				disks[0].HostPath = filepath.Join(dataDir, "missing.img")
			case "directory":
				disks[0].HostPath = dataDir
			}
			_, err := Run(context.Background(), "unused",
				WithDataDir(dataDir), WithCleanDataDir(), WithDisks(disks...),
				optionFunc(func(c *config) {
					c.processAlive = func(int) bool {
						t.Error("invalid disks must not trigger stale runner cleanup")
						return false
					}
				}),
			)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "WithCleanDataDir", "reject invalid options before cleanup checks")
			got, err := os.ReadFile(statePath) //nolint:gosec // test-controlled path
			require.NoError(t, err)
			assert.Equal(t, state, got)
			got, err = os.ReadFile(diskPath) //nolint:gosec // test-controlled path
			require.NoError(t, err)
			assert.Equal(t, "disk contents", string(got))
		})
	}
}

func TestRun_DisksWithCleanup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dataDir  string
		disk     string
		rootfs   string
		cache    string
		hardLink string
		wantErr  string
	}{
		{name: "deleted disk", disk: "data/discard/data.img", wantErr: "would be removed"},
		{name: "preserved cache", disk: "data/cache/data.img"},
		{name: "preserved rootfs", disk: "data/rootfs/data.img"},
		{name: "external disk", disk: "external/data.img"},
		{name: "external hard-linked disk", disk: "external/data.img", hardLink: "data/old.img"},
		{name: "external hard link with same name", disk: "external/data.img", hardLink: "data/data.img"},
		{name: "direct hard-linked disk is deleted", disk: "data/data.img", hardLink: "external/old.img", wantErr: "would be removed"},
		{name: "sibling prefix", disk: "data-other/data.img"},
		{name: "nested cache is not preserved", disk: "data/nested/cache/data.img", cache: "data/nested/cache", wantErr: "would be removed"},
		{name: "nested rootfs is not preserved", disk: "data/nested/rootfs/data.img", rootfs: "data/nested/rootfs", wantErr: "would be removed"},
		{name: "whole directory removed", disk: "data/discard/data.img", cache: "external/cache", rootfs: "external/rootfs", wantErr: "would be removed"},
		{name: "data directory alias", dataDir: "alias", disk: "data/discard/data.img", wantErr: "would be removed"},
		{name: "preserved through data directory alias", dataDir: "alias", disk: "alias/cache/data.img"},
		{name: "canonical disk with aliased data directory", dataDir: "alias", disk: "data/cache/data.img"},
		{name: "disk alias into deleted directory", disk: "alias/discard/data.img", wantErr: "would be removed"},
		{name: "disk alias out of deleted directory", disk: "data/outward/data.img", wantErr: "would be removed"},
		{name: "indirect disk alias", disk: "chain/data.img"},
		{name: "preserved alias", disk: "alias/cache/data.img"},
		{name: "non-normalized directory", dataDir: "data/../data/.", disk: "data/cache/data.img"},
		{name: "non-normalized disk", disk: "data/cache/../cache/data.img"},
		{name: "whole directory link removed", dataDir: "alias", disk: "data/discard/data.img", cache: "external/cache", rootfs: "external/rootfs"},
		{name: "disk through removed directory link", dataDir: "alias", disk: "alias/discard/data.img", cache: "external/cache", rootfs: "external/rootfs", wantErr: "would be removed"},
		{name: "shared ancestor alias", dataDir: "shared/data", disk: "shared/external/data.img"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base, err := filepath.EvalSymlinks(t.TempDir())
			require.NoError(t, err)
			dataDir := filepath.Join(base, "data")
			require.NoError(t, os.MkdirAll(dataDir, 0o700))
			require.NoError(t, os.MkdirAll(filepath.Join(base, "external"), 0o700))
			require.NoError(t, os.Symlink(dataDir, filepath.Join(base, "alias")))
			require.NoError(t, os.Symlink(filepath.Join(base, "external"), filepath.Join(dataDir, "outward")))
			require.NoError(t, os.Symlink(filepath.Join(dataDir, "outward"), filepath.Join(base, "chain")))
			require.NoError(t, os.Symlink(base, filepath.Join(base, "shared")))
			if tt.dataDir != "" {
				dataDir = base + "/" + tt.dataDir
			}
			rootfs := filepath.Join(dataDir, "rootfs")
			if tt.rootfs != "" {
				rootfs = filepath.Join(base, tt.rootfs)
			}
			require.NoError(t, os.MkdirAll(rootfs, 0o700))
			diskPath := base + "/" + tt.disk
			require.NoError(t, os.MkdirAll(filepath.Dir(diskPath), 0o700))
			require.NoError(t, os.WriteFile(diskPath, []byte("disk contents"), 0o600))
			if tt.hardLink != "" {
				require.NoError(t, os.Link(diskPath, filepath.Join(base, tt.hardLink)))
			}
			resolvedDisk, err := filepath.EvalSymlinks(diskPath)
			require.NoError(t, err)
			statePath := filepath.Join(dataDir, "go-microvm-state.json")
			state := []byte(`{"version":1,"active":true,"pid":1234}`)
			require.NoError(t, os.WriteFile(statePath, state, 0o600))

			backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
			disk := Disk{ID: "data", HostPath: diskPath}
			opts := []Option{
				WithDataDir(dataDir), WithCleanDataDir(), WithRootFSPath(rootfs),
				WithDisks(disk), WithBackend(backend), WithPreflightChecker(preflight.NewEmpty()),
				optionFunc(func(c *config) {
					c.processAlive = func(int) bool {
						if tt.wantErr != "" {
							t.Error("conflicting disks must not trigger stale runner cleanup")
						}
						return false
					}
				}),
			}
			if tt.cache != "" {
				opts = append(opts, WithImageCache(image.NewCache(filepath.Join(base, tt.cache))))
			}
			vm, err := Run(context.Background(), "unused", opts...)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Zero(t, backend.startCalls)
				got, readErr := os.ReadFile(statePath) //nolint:gosec // test-controlled path
				require.NoError(t, readErr)
				assert.Equal(t, state, got)
				if tt.hardLink != "" {
					got, readErr = os.ReadFile(filepath.Join(base, tt.hardLink))
					require.NoError(t, readErr)
					assert.Equal(t, "disk contents", string(got))
				}
			} else {
				require.NoError(t, err)
				t.Cleanup(func() { _ = vm.Stop(context.Background()) })
				if tt.hardLink != "" {
					_, statErr := os.Lstat(filepath.Join(base, tt.hardLink))
					assert.True(t, os.IsNotExist(statErr), "cleanup must unlink the redundant hard link")
				}
				disk.HostPath = resolvedDisk
				assert.Equal(t, toHypervisorDisks([]Disk{disk}), backend.lastConfig.Disks)
				if tt.name == "whole directory link removed" {
					info, statErr := os.Lstat(dataDir)
					require.NoError(t, statErr)
					assert.True(t, info.IsDir(), "cleanup must unlink the alias, not wipe its target")
					got, readErr := os.ReadFile(filepath.Join(base, "data", "go-microvm-state.json"))
					require.NoError(t, readErr)
					assert.Equal(t, state, got)
				}
				if tt.name == "indirect disk alias" {
					_, statErr := os.Stat(diskPath)
					assert.True(t, os.IsNotExist(statErr), "startup must use the surviving resolved target")
				}
			}
			got, err := os.ReadFile(resolvedDisk)
			require.NoError(t, err)
			assert.Equal(t, "disk contents", string(got))
		})
	}
}

func TestRun_DiskCleanupCaseInsensitiveAliases(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		dataDir string
		disk    string
		cache   string
	}{
		{name: "data directory case", dataDir: "data", disk: "DATA/discard/data.img"},
		{name: "cleanup directory case", dataDir: "DATA", disk: "data/discard/data.img"},
		{name: "entry case", dataDir: "data", disk: "data/DISCARD/data.img"},
		{name: "file case", dataDir: "data", disk: "data/discard/DATA.IMG"},
		{name: "top-level file case", dataDir: "data", disk: "data/DATA.IMG"},
		{name: "whole directory case", dataDir: "data", disk: "DATA/discard/data.img", cache: "external/cache"},
		{name: "keep spelling differs from entry", dataDir: "data", disk: "data/cache/data.img", cache: "data/CACHE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			dataDir := filepath.Join(base, "data")
			require.NoError(t, os.Mkdir(dataDir, 0o700))
			info, err := os.Stat(dataDir)
			require.NoError(t, err)
			aliasInfo, err := os.Stat(filepath.Join(base, "DATA"))
			if os.IsNotExist(err) {
				t.Skip("filesystem is case-sensitive")
			}
			require.NoError(t, err)
			if !os.SameFile(info, aliasInfo) {
				t.Skip("filesystem is case-sensitive")
			}

			diskDir := filepath.Join(dataDir, "discard")
			if tt.cache == "data/CACHE" {
				diskDir = filepath.Join(dataDir, "cache")
			}
			if tt.disk == "data/DATA.IMG" {
				diskDir = dataDir
			}
			require.NoError(t, os.MkdirAll(diskDir, 0o700))
			diskPath := filepath.Join(diskDir, "data.img")
			require.NoError(t, os.WriteFile(diskPath, []byte("disk contents"), 0o600))
			statePath := filepath.Join(dataDir, "go-microvm-state.json")
			state := []byte(`{"version":1,"active":true,"pid":1234}`)
			require.NoError(t, os.WriteFile(statePath, state, 0o600))
			opts := []Option{
				WithDataDir(filepath.Join(base, tt.dataDir)), WithCleanDataDir(),
				WithDisks(Disk{ID: "data", HostPath: filepath.Join(base, tt.disk)}),
				optionFunc(func(c *config) {
					c.processAlive = func(int) bool {
						t.Error("conflicting disks must not trigger stale runner cleanup")
						return false
					}
				}),
			}
			if tt.cache != "" {
				opts = append(opts, WithImageCache(image.NewCache(filepath.Join(base, tt.cache))))
			}
			_, err = Run(context.Background(), "unused", opts...)
			require.ErrorContains(t, err, "would be removed")
			got, err := os.ReadFile(statePath) //nolint:gosec // test-controlled path
			require.NoError(t, err)
			assert.Equal(t, state, got)
			got, err = os.ReadFile(diskPath) //nolint:gosec // test-controlled path
			require.NoError(t, err)
			assert.Equal(t, "disk contents", string(got))
		})
	}
}

func TestToHypervisorDisks(t *testing.T) {
	t.Parallel()

	assert.Nil(t, toHypervisorDisks(nil))

	out := toHypervisorDisks([]Disk{
		{ID: "data", HostPath: "/d/data.img"},
		{ID: "seed", HostPath: "/d/seed.qcow2", Format: DiskFormatQCOW2, ReadOnly: true},
	})
	require.Len(t, out, 2)
	assert.Equal(t, "data", out[0].ID)
	assert.Equal(t, "/d/data.img", out[0].HostPath)
	assert.Equal(t, "raw", out[0].Format, "empty format defaults to raw")
	assert.False(t, out[0].ReadOnly)
	assert.Equal(t, "qcow2", out[1].Format)
	assert.True(t, out[1].ReadOnly)
}
