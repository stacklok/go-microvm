// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Composed rootfs snapshots
//
// Composing a rootfs applies every layer of the image, bottom to top, even
// when only the top layers differ from an image extracted before. Where the
// file system can clone a whole directory tree at once (APFS), the cache
// keeps snapshots of composed layer prefixes, keyed by their OCI ChainID, and
// starts a new composition from the longest snapshot or cached rootfs that
// matches a prefix of the image's layers.
//
// A snapshot is taken at the longest prefix an image shares with another
// cached image: that is where rebuilt images diverge, e.g. a changed
// Dockerfile instruction near the top. Each cached rootfs records its layer
// list in chains/ to find these prefixes.

const (
	snapshotDir = "snapshots"
	chainDir    = "chains"
)

// errCloneTreeUnsupported reports a platform without directory clones.
var errCloneTreeUnsupported = errors.New("directory clone not supported")

// chainIDs returns the OCI ChainIDs of every layer prefix: element i
// identifies the layers 0..i applied in order.
func chainIDs(diffIDs []v1.Hash) []string {
	ids := make([]string, len(diffIDs))
	prev := ""
	for i, d := range diffIDs {
		if i == 0 {
			prev = d.String()
		} else {
			sum := sha256.Sum256([]byte(prev + " " + d.String()))
			prev = "sha256:" + hex.EncodeToString(sum[:])
		}
		ids[i] = prev
	}
	return ids
}

// composeBase is where a composition starts: path holds the first layers
// of the image applied.
type composeBase struct {
	layers int
	path   string
}

// findComposeBase returns the longest snapshot or cached rootfs that holds a
// prefix of the image whose layer prefixes chain identifies, or zero layers.
func (c *Cache) findComposeBase(chain []string) composeBase {
	var best composeBase
	if c == nil {
		return best
	}
	for i := len(chain) - 1; i >= 0; i-- {
		dir := c.snapshotPath(chain[i])
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			best = composeBase{layers: i + 1, path: dir}
			break
		}
	}
	for digest, ids := range c.recordedChains() {
		k := len(ids)
		if k <= best.layers || k > len(chain) || ids[k-1] != chain[k-1] {
			continue
		}
		if path, ok := c.Get(digest); ok {
			best = composeBase{layers: k, path: path}
		}
	}
	if best.path != "" {
		now := time.Now()
		_ = os.Chtimes(best.path, now, now)
	}
	return best
}

// sharedPrefix returns the number of leading layers the image shares with
// the longest-matching other cached rootfs.
func (c *Cache) sharedPrefix(chain []string) int {
	shared := 0
	for digest, ids := range c.recordedChains() {
		if _, ok := c.Get(digest); !ok {
			continue
		}
		k := 0
		for k < len(ids) && k < len(chain) && ids[k] == chain[k] {
			k++
		}
		shared = max(shared, k)
	}
	return shared
}

// recordedChains reads the layer prefix ChainIDs of the cached rootfs
// entries, keyed by image digest.
func (c *Cache) recordedChains() map[string][]string {
	out := map[string][]string{}
	if c == nil {
		return out
	}
	entries, err := os.ReadDir(filepath.Join(c.baseDir, chainDir))
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !isRootfsEntry(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.baseDir, chainDir, e.Name()))
		if err != nil {
			continue
		}
		var diffIDs []v1.Hash
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			h, err := v1.NewHash(strings.TrimSpace(sc.Text()))
			if err != nil {
				diffIDs = nil
				break
			}
			diffIDs = append(diffIDs, h)
		}
		if len(diffIDs) > 0 {
			out[dirNameToDigest(e.Name())] = chainIDs(diffIDs)
		}
	}
	return out
}

// recordChain stores the layer list of the cached rootfs for digest.
// Best-effort: without it the entry is only missing as a compose base.
func (c *Cache) recordChain(digest string, diffIDs []v1.Hash) {
	if c == nil || len(diffIDs) == 0 {
		return
	}
	dir := filepath.Join(c.baseDir, chainDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	var b strings.Builder
	for _, d := range diffIDs {
		b.WriteString(d.String() + "\n")
	}
	_ = os.WriteFile(filepath.Join(dir, filepath.Base(c.pathFor(digest))), []byte(b.String()), 0o600)
}

// putSnapshot keeps a clone of the composed rootfs src as the snapshot of
// the layer prefix chainID. Best-effort: snapshots only speed up later
// compositions, and platforms without directory clones keep none.
func (c *Cache) putSnapshot(chainID, src string) {
	dst := c.snapshotPath(chainID)
	if _, err := os.Stat(dst); err == nil {
		return
	}
	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return
	}
	tmp, err := os.MkdirTemp(parent, "tmp-snapshot-*")
	if err != nil {
		return
	}
	_ = os.Remove(tmp)
	if err := cloneTree(src, tmp); err != nil {
		if !errors.Is(err, errCloneTreeUnsupported) {
			slog.Debug("snapshot of composed rootfs failed", "chainID", chainID, "err", err)
		}
		_ = removeTree(tmp)
		return
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = removeTree(tmp)
	}
}

// startFrom clones base into dst, an empty directory. It reports whether dst
// now holds the base layers. The clone keeps the override_stat xattrs, which
// carry the guest-visible owners and modes, setuid and setgid included.
func startFrom(base composeBase, dst string) bool {
	if base.layers == 0 {
		return false
	}
	if err := os.Remove(dst); err != nil {
		return false
	}
	if err := cloneTree(base.path, dst); err != nil {
		_ = removeTree(dst)
		if mkErr := os.Mkdir(dst, 0o700); mkErr != nil {
			slog.Debug("recreate rootfs directory failed", "path", dst, "err", mkErr)
		}
		return false
	}
	return true
}

// PruneSnapshots removes the snapshots that are not a layer prefix of any
// cached rootfs, unless they were used within grace, and the layer lists of
// rootfs entries that no longer exist. It returns the number of snapshots
// removed.
func (c *Cache) PruneSnapshots(grace time.Duration) (int, error) {
	if c == nil {
		return 0, nil
	}
	live := map[string]bool{}
	for digest, ids := range c.recordedChains() {
		if _, err := os.Stat(c.pathFor(digest)); err != nil {
			_ = os.Remove(filepath.Join(c.baseDir, chainDir, filepath.Base(c.pathFor(digest))))
			continue
		}
		for _, id := range ids {
			live[id] = true
		}
	}
	dir := filepath.Join(c.baseDir, snapshotDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read snapshot dir: %w", err)
	}
	cutoff := time.Now().Add(-grace)
	removed := 0
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if live[dirNameToDigest(e.Name())] {
			continue
		}
		if err := removeTree(path); err != nil {
			return removed, fmt.Errorf("remove snapshot %s: %w", e.Name(), err)
		}
		removed++
	}
	return removed, nil
}

func (c *Cache) snapshotPath(chainID string) string {
	return filepath.Join(c.baseDir, snapshotDir, filepath.Base(c.pathFor(chainID)))
}

// removeTree deletes path, first making its directories writable: composed
// rootfs trees keep read-only directories from the image.
func removeTree(path string) error {
	if err := os.RemoveAll(path); err == nil {
		return nil
	}
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700) //nolint:gosec // owner-only, the tree is about to be removed
		}
		return nil
	})
	return os.RemoveAll(path)
}
