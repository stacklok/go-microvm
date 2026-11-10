// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package vhd

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
)

const (
	// DefaultMaxDiskSize is the default maximum ext4 filesystem size.
	DefaultMaxDiskSize int64 = 16 * 1024 * 1024 * 1024
	// RootFSVHDName is the conventional rootfs VHD filename.
	RootFSVHDName = "rootfs.vhd"
)

type options struct {
	maxDiskSize int64
}

// Option configures a rootfs VHD build.
type Option func(*options)

// WithMaxDiskSize sets the maximum ext4 filesystem size in bytes.
func WithMaxDiskSize(bytes int64) Option {
	return func(opts *options) {
		opts.maxDiskSize = bytes
	}
}

// BuildFromDir creates a fixed ext4 VHD containing the entries under rootfsDir.
func BuildFromDir(ctx context.Context, rootfsDir, outVHDPath string, opts ...Option) (retErr error) {
	if outVHDPath == "" {
		return errors.New("output VHD path is empty")
	}
	rootInfo, err := os.Stat(rootfsDir)
	if err != nil {
		return fmt.Errorf("stat rootfs directory: %w", err)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("rootfs path is not a directory: %q", rootfsDir)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("build rootfs VHD: %w", err)
	}

	buildOptions := options{maxDiskSize: DefaultMaxDiskSize}
	for _, opt := range opts {
		opt(&buildOptions)
	}

	tempPath := outVHDPath + ".tmp"
	outFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary VHD: %w", err)
	}
	outFileClosed := false
	defer func() {
		if !outFileClosed {
			closeErr := outFile.Close()
			if closeErr != nil && retErr == nil {
				retErr = fmt.Errorf("close temporary VHD: %w", closeErr)
			}
		}
		if retErr != nil {
			if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove temporary VHD: %w", removeErr))
			}
		}
	}()

	pipeReader, pipeWriter := io.Pipe()
	tarErr := make(chan error, 1)
	go func() {
		err := writeTar(ctx, pipeWriter, rootfsDir, outVHDPath, tempPath)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
		} else {
			err = pipeWriter.Close()
		}
		tarErr <- err
	}()

	convertErr := tar2ext4.Convert(
		pipeReader,
		outFile,
		tar2ext4.ConvertWhiteout,
		tar2ext4.AppendVhdFooter,
		tar2ext4.MaximumDiskSize(buildOptions.maxDiskSize),
	)
	if closeErr := pipeReader.CloseWithError(convertErr); convertErr == nil && closeErr != nil {
		convertErr = closeErr
	}
	streamErr := <-tarErr
	if convertErr != nil {
		return fmt.Errorf("convert rootfs tar to ext4 VHD: %w", convertErr)
	}
	if streamErr != nil {
		return fmt.Errorf("stream rootfs tar: %w", streamErr)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("build rootfs VHD: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close temporary VHD: %w", err)
	}
	outFileClosed = true
	if err := os.Rename(tempPath, outVHDPath); err != nil {
		return fmt.Errorf("rename temporary VHD: %w", err)
	}
	return nil
}

func writeTar(ctx context.Context, pipeWriter *io.PipeWriter, rootfsDir, outVHDPath, tempPath string) error {
	tarWriter := tar.NewWriter(pipeWriter)
	walkErr := filepath.WalkDir(rootfsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if samePath(path, outVHDPath) || samePath(path, tempPath) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		relPath, err := filepath.Rel(rootfsDir, path)
		if err != nil {
			return fmt.Errorf("compute relative path for %q: %w", path, err)
		}
		if relPath == "." {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat %q: %w", relPath, err)
		}
		if !info.Mode().IsRegular() && !info.IsDir() && info.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("unsupported rootfs entry %q with mode %s", relPath, info.Mode())
		}

		linkTarget := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("read symlink %q: %w", relPath, err)
			}
			if !filepath.IsAbs(linkTarget) && relativeSymlinkEscapes(rootfsDir, path, linkTarget) {
				return nil
			}
		}

		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return fmt.Errorf("create tar header for %q: %w", relPath, err)
		}
		header.Name = filepath.ToSlash(relPath)
		header.Format = tar.FormatPAX
		setHeaderMetadata(path, header, info, header.Name)
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header for %q: %w", relPath, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open rootfs file %q: %w", relPath, err)
		}
		_, copyErr := io.Copy(tarWriter, &contextReader{ctx: ctx, reader: file})
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("write rootfs file %q: %w", relPath, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close rootfs file %q: %w", relPath, closeErr)
		}
		return nil
	})
	if walkErr != nil {
		if closeErr := tarWriter.Close(); closeErr != nil {
			return errors.Join(walkErr, fmt.Errorf("close rootfs tar: %w", closeErr))
		}
		return walkErr
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close rootfs tar: %w", err)
	}
	return nil
}

func setHeaderMetadata(path string, header *tar.Header, info fs.FileInfo, tarPath string) {
	uid, gid, mode, ok := getOverrideStat(path)
	if ok {
		header.Uid = uid
		header.Gid = gid
		header.Mode = mode & 0o7777
		return
	}

	mode = int64(info.Mode().Perm())
	if info.Mode()&os.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if info.Mode()&os.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if runtime.GOOS == "windows" && info.Mode().IsRegular() && shouldBeExecutable(tarPath) {
		mode = 0o755
	}
	header.Mode = mode
}

func shouldBeExecutable(tarPath string) bool {
	if tarPath == ".krun_init" || tarPath == "init" {
		return true
	}
	for _, prefix := range []string{
		"bin/",
		"sbin/",
		"usr/bin/",
		"usr/sbin/",
		"usr/local/bin/",
		"usr/local/sbin/",
		"etc/init.d/",
	} {
		if strings.HasPrefix(tarPath, prefix) {
			return true
		}
	}
	return false
}

func relativeSymlinkEscapes(rootfsDir, symlinkPath, target string) bool {
	resolved := filepath.Clean(filepath.Join(filepath.Dir(symlinkPath), target))
	relPath, err := filepath.Rel(rootfsDir, resolved)
	return err != nil || relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator))
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
