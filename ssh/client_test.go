// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellEscape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty string", input: "", expected: "''"},
		{name: "simple", input: "hello", expected: "'hello'"},
		{name: "with spaces", input: "hello world", expected: "'hello world'"},
		{name: "with single quote", input: "it's", expected: `'it'\''s'`},
		{name: "with double quotes", input: `say "hi"`, expected: `'say "hi"'`},
		{name: "with backtick", input: "echo `cmd`", expected: "'echo `cmd`'"},
		{name: "with newline", input: "line1\nline2", expected: "'line1\nline2'"},
		{name: "with dollar sign", input: "$HOME", expected: "'$HOME'"},
		{name: "with semicolons", input: "cmd1; cmd2", expected: "'cmd1; cmd2'"},
		{name: "with pipe", input: "ls | grep foo", expected: "'ls | grep foo'"},
		{name: "multiple single quotes", input: "it's a 'test'", expected: `'it'\''s a '\''test'\'''`},
		{name: "path with spaces", input: "/path/to/my file.txt", expected: "'/path/to/my file.txt'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ShellEscape(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	c := NewClient("192.168.127.2", 22, "root", "/tmp/id_ecdsa")

	assert.Equal(t, "192.168.127.2", c.host)
	assert.Equal(t, uint16(22), c.port)
	assert.Equal(t, "root", c.user)
	assert.Equal(t, "/tmp/id_ecdsa", c.keyPath)
	assert.NotNil(t, c.readFile, "readFile should default to os.ReadFile")
	assert.NotNil(t, c.writeFile, "writeFile should default to os.WriteFile")
}

func TestNewClient_Defaults(t *testing.T) {
	t.Parallel()

	c := NewClient("localhost", 2222, "admin", "/home/user/.ssh/id_ecdsa")
	assert.Equal(t, "localhost", c.host)
	assert.Equal(t, uint16(2222), c.port)
	assert.Equal(t, "admin", c.user)
	assert.Equal(t, "/home/user/.ssh/id_ecdsa", c.keyPath)
}

func TestCopyTo_ReadError(t *testing.T) {
	t.Parallel()

	c := NewClient("127.0.0.1", 22, "root", "/tmp/key")
	c.readFile = func(_ string) ([]byte, error) {
		return nil, fmt.Errorf("mock read error")
	}

	err := c.CopyTo(context.Background(), "/nonexistent/file", "/remote/path", 0o644)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read local file")
}

func TestSSHConfig_ReadKeyError(t *testing.T) {
	t.Parallel()

	c := NewClient("127.0.0.1", 22, "root", "/nonexistent/key")
	c.readFile = func(_ string) ([]byte, error) {
		return nil, fmt.Errorf("key file not found")
	}

	_, err := c.Run(context.Background(), "echo hi")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read SSH key")
}

func TestRunSudo_FailsAtKeyRead(t *testing.T) {
	t.Parallel()

	c := NewClient("127.0.0.1", 22, "root", "/key")
	c.readFile = func(_ string) ([]byte, error) {
		return nil, fmt.Errorf("no key")
	}

	_, err := c.RunSudo(context.Background(), "whoami")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read SSH key")
}
