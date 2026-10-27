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

func TestWithEnv_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithEnv("A=1").apply(cfg)
	WithEnv("B=2", "C=3").apply(cfg)

	assert.Equal(t, []string{"A=1", "B=2", "C=3"}, cfg.env)
}

func TestBuildInitConfig_WithEnv(t *testing.T) {
	t.Parallel()

	const defaultPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	tests := []struct {
		name     string
		imageEnv []string
		env      []string
		want     []string
	}{
		{
			name:     "no extra env keeps image env",
			imageEnv: []string{"FOO=image"},
			want:     []string{defaultPath, "FOO=image"},
		},
		{
			name:     "new key is appended",
			imageEnv: []string{"FOO=image"},
			env:      []string{"KRUN_INIT_PID1=1"},
			want:     []string{defaultPath, "FOO=image", "KRUN_INIT_PID1=1"},
		},
		{
			name:     "image key is replaced in place",
			imageEnv: []string{"FOO=image", "BAR=image"},
			env:      []string{"FOO=override"},
			want:     []string{defaultPath, "FOO=override", "BAR=image"},
		},
		{
			name:     "duplicate HOME entries are removed when overridden",
			imageEnv: []string{"HOME=/one", "BAR=image", "HOME=/two"},
			env:      []string{"HOME=/custom"},
			want:     []string{defaultPath, "HOME=/custom", "BAR=image"},
		},
		{
			name:     "duplicate TERM entries are removed when overridden",
			imageEnv: []string{"TERM=linux", "TERM=vt100"},
			env:      []string{"TERM=xterm"},
			want:     []string{defaultPath, "TERM=xterm"},
		},
		{
			name:     "duplicate ordinary keys and later overrides",
			imageEnv: []string{"FOO=one", "FOO=two", "BAR=image"},
			env:      []string{"FOO=first", "BAR=override", "FOO=last", "NEW=value"},
			want:     []string{defaultPath, "FOO=last", "BAR=override", "NEW=value"},
		},
		{
			name:     "unoverridden duplicates are preserved",
			imageEnv: []string{"HOME=/one", "HOME=/two", "FOO=one", "FOO=two"},
			env:      []string{"BAR=extra"},
			want:     []string{defaultPath, "HOME=/one", "HOME=/two", "FOO=one", "FOO=two", "BAR=extra"},
		},
		{
			name:     "no extra env preserves duplicates",
			imageEnv: []string{"HOME=/one", "HOME=/two"},
			want:     []string{defaultPath, "HOME=/one", "HOME=/two"},
		},
		{
			name:     "default and image PATH are replaced",
			imageEnv: []string{"PATH=/image/bin"},
			env:      []string{"PATH=/opt/bin"},
			want:     []string{"PATH=/opt/bin"},
		},
		{
			name: "default PATH is replaced",
			env:  []string{"PATH=/opt/bin"},
			want: []string{"PATH=/opt/bin"},
		},
		{
			name: "later entry wins",
			env:  []string{"FOO=first", "FOO=second"},
			want: []string{defaultPath, "FOO=second"},
		},
		{
			name: "empty value is kept",
			env:  []string{"EMPTY="},
			want: []string{defaultPath, "EMPTY="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := defaultConfig()
			cfg.env = tt.env
			ic := buildInitConfig(&image.OCIConfig{Env: tt.imageEnv}, cfg)

			assert.Equal(t, tt.want, ic.Env)
		})
	}
}

func TestBuildInitConfig_WithEnvDoesNotMutateImageEnv(t *testing.T) {
	t.Parallel()

	imageEnv := []string{"FOO=image"}
	cfg := defaultConfig()
	cfg.env = []string{"FOO=override"}
	buildInitConfig(&image.OCIConfig{Env: imageEnv}, cfg)

	assert.Equal(t, []string{"FOO=image"}, imageEnv)
}

func TestValidateEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     []string
		wantErr string
	}{
		{name: "nil"},
		{name: "valid", env: []string{"A=1", "B=", "C=x=y"}},
		{name: "missing equals", env: []string{"A=1", "B"}, wantErr: `env[1] "B"`},
		{name: "empty key", env: []string{"=1"}, wantErr: `env[0] "=1"`},
		{name: "empty entry", env: []string{""}, wantErr: `env[0] ""`},
		{name: "NUL in key", env: []string{"TO\x00KEN=value"}, wantErr: "env[0]: NUL bytes are not allowed"},
		{name: "NUL in value", env: []string{"A=1", "TOKEN=before\x00after"}, wantErr: "env[1]: NUL bytes are not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateEnv(tt.env)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRun_RejectsInvalidEnvBeforeCreatingDataDir(t *testing.T) {
	t.Parallel()

	dataDir := filepath.Join(t.TempDir(), "data")
	backend := &mockBackend{}

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithBackend(backend),
		WithEnv("NOT_A_PAIR"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOT_A_PAIR")
	assert.Zero(t, backend.startCalls)
	_, statErr := os.Stat(dataDir)
	assert.True(t, os.IsNotExist(statErr), "data dir must not be created")
}

func TestRun_WithEnv_ReachesBackend(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o750))

	backend := &mockBackend{startHandle: &mockVMHandle{id: "1234", alive: true}}

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(&mockNetProvider{sockPath: "/tmp/fake.sock"}),
		WithBackend(backend),
		WithInitOverride("/lib/systemd/systemd"),
		WithEnv("KRUN_INIT_PID1=1"),
	)
	require.NoError(t, err)

	assert.Contains(t, backend.lastConfig.InitConfig.Env, "KRUN_INIT_PID1=1")
	assert.Equal(t, []string{"/lib/systemd/systemd"}, backend.lastConfig.InitConfig.Cmd)
}
