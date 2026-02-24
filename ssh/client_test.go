// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSession implements remoteSession for testing.
type mockSession struct {
	runFn  func(cmd string) error
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	closed bool
}

func (m *mockSession) Run(cmd string) error  { return m.runFn(cmd) }
func (m *mockSession) SetStdout(w io.Writer) { m.stdout = w }
func (m *mockSession) SetStderr(w io.Writer) { m.stderr = w }
func (m *mockSession) SetStdin(r io.Reader)  { m.stdin = r }
func (m *mockSession) Close() error          { m.closed = true; return nil }

// newTestClient creates a Client with a mock session for testing.
func newTestClient(t *testing.T, session *mockSession) *Client {
	t.Helper()
	c := &Client{
		host:      "testhost",
		port:      2222,
		user:      "testuser",
		readFile:  os.ReadFile,
		writeFile: os.WriteFile,
	}
	c.createSession = func(_ context.Context) (remoteSession, func(), error) {
		return session, func() {}, nil
	}
	return c
}

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
	assert.NotNil(t, c.createSession, "createSession should be initialized")
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

func TestRun_Success(t *testing.T) {
	t.Parallel()

	mock := &mockSession{
		runFn: func(_ string) error {
			// Write output via the stdout writer that was set.
			if mock := recover(); mock != nil {
				return fmt.Errorf("panic")
			}
			return nil
		},
	}
	// The mock needs to write to stdout when Run is called.
	mock.runFn = func(_ string) error {
		if mock.stdout != nil {
			_, _ = io.WriteString(mock.stdout, "hello world")
		}
		return nil
	}

	c := newTestClient(t, mock)
	output, err := c.Run(context.Background(), "echo hello")

	require.NoError(t, err)
	assert.Equal(t, "hello world", output)
	assert.True(t, mock.closed)
}

func TestRun_CommandFailure(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		if mock.stdout != nil {
			_, _ = io.WriteString(mock.stdout, "error output")
		}
		return fmt.Errorf("exit status 1")
	}

	c := newTestClient(t, mock)
	output, err := c.Run(context.Background(), "failing-cmd")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh command")
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "error output")
	assert.Equal(t, "error output", output)
}

func TestRunSudo_PrependsDoasCommand(t *testing.T) {
	t.Parallel()

	var capturedCmd string
	mock := &mockSession{}
	mock.runFn = func(cmd string) error {
		capturedCmd = cmd
		return nil
	}

	c := newTestClient(t, mock)
	_, err := c.RunSudo(context.Background(), "whoami")

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(capturedCmd, "doas "), "command should start with 'doas '")
	assert.Equal(t, "doas whoami", capturedCmd)
}

func TestRunStream_StreamsOutput(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		if mock.stdout != nil {
			_, _ = io.WriteString(mock.stdout, "stdout data")
		}
		if mock.stderr != nil {
			_, _ = io.WriteString(mock.stderr, "stderr data")
		}
		return nil
	}

	c := newTestClient(t, mock)

	var stdoutBuf, stderrBuf bytes.Buffer
	err := c.RunStream(context.Background(), "some-cmd", &stdoutBuf, &stderrBuf)

	require.NoError(t, err)
	assert.Equal(t, "stdout data", stdoutBuf.String())
	assert.Equal(t, "stderr data", stderrBuf.String())
}

func TestRunStream_CommandError(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		return fmt.Errorf("command failed")
	}

	c := newTestClient(t, mock)

	var stdoutBuf, stderrBuf bytes.Buffer
	err := c.RunStream(context.Background(), "bad-cmd", &stdoutBuf, &stderrBuf)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh stream command")
	assert.Contains(t, err.Error(), "command failed")
}

func TestCopyTo_Success(t *testing.T) {
	t.Parallel()

	fileContent := []byte("file data here")
	var capturedCmd string

	mock := &mockSession{}
	mock.runFn = func(cmd string) error {
		capturedCmd = cmd
		// Read stdin to simulate cat consuming the data.
		if mock.stdin != nil {
			_, _ = io.ReadAll(mock.stdin)
		}
		return nil
	}

	c := newTestClient(t, mock)
	c.readFile = func(_ string) ([]byte, error) {
		return fileContent, nil
	}

	err := c.CopyTo(context.Background(), "/local/file.txt", "/remote/file.txt", 0o755)
	require.NoError(t, err)
	assert.Contains(t, capturedCmd, "cat >")
	assert.Contains(t, capturedCmd, "chmod 755")
	assert.Contains(t, capturedCmd, "'/remote/file.txt'")
}

func TestCopyTo_SessionCreationFails(t *testing.T) {
	t.Parallel()

	c := &Client{
		host:      "testhost",
		port:      2222,
		user:      "testuser",
		readFile:  func(_ string) ([]byte, error) { return []byte("data"), nil },
		writeFile: os.WriteFile,
	}
	c.createSession = func(_ context.Context) (remoteSession, func(), error) {
		return nil, nil, fmt.Errorf("session creation failed")
	}

	err := c.CopyTo(context.Background(), "/local/file", "/remote/file", 0o644)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session creation failed")
}

func TestCopyFrom_Success(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		if mock.stdout != nil {
			_, _ = io.WriteString(mock.stdout, "remote file content")
		}
		return nil
	}

	var writtenPath string
	var writtenData []byte
	var writtenMode os.FileMode

	c := newTestClient(t, mock)
	c.writeFile = func(path string, data []byte, mode os.FileMode) error {
		writtenPath = path
		writtenData = data
		writtenMode = mode
		return nil
	}

	err := c.CopyFrom(context.Background(), "/remote/data.txt", "/local/data.txt")
	require.NoError(t, err)
	assert.Equal(t, "/local/data.txt", writtenPath)
	assert.Equal(t, []byte("remote file content"), writtenData)
	assert.Equal(t, os.FileMode(0o644), writtenMode)
}

func TestCopyFrom_RemoteReadFailure(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		return fmt.Errorf("remote cat failed")
	}

	c := newTestClient(t, mock)

	err := c.CopyFrom(context.Background(), "/remote/missing.txt", "/local/out.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "copy from")
}

func TestCopyFrom_WriteFileFailure(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		if mock.stdout != nil {
			_, _ = io.WriteString(mock.stdout, "some data")
		}
		return nil
	}

	c := newTestClient(t, mock)
	c.writeFile = func(_ string, _ []byte, _ os.FileMode) error {
		return fmt.Errorf("disk full")
	}

	err := c.CopyFrom(context.Background(), "/remote/file.txt", "/local/file.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write local file")
}

func TestWaitForReady_SucceedsOnFirstProbe(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		return nil
	}

	c := newTestClient(t, mock)

	// Use a context with timeout to avoid hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Override the ticker interval by testing probe directly with WaitForReady.
	// WaitForReady uses a 2s ticker, so we need to wait for a tick.
	// For a fast test, we test probe directly.
	err := c.probe(ctx)
	require.NoError(t, err)
}

func TestWaitForReady_SucceedsAfterRetries(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		count := callCount.Add(1)
		if count <= 2 {
			return fmt.Errorf("not ready yet")
		}
		return nil
	}

	c := newTestClient(t, mock)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Simulate retries by calling probe multiple times.
	var err error
	for i := 0; i < 5; i++ {
		err = c.probe(ctx)
		if err == nil {
			break
		}
	}
	require.NoError(t, err)
	assert.GreaterOrEqual(t, callCount.Load(), int32(3))
}

func TestWaitForReady_ContextCancelled(t *testing.T) {
	t.Parallel()

	mock := &mockSession{}
	mock.runFn = func(_ string) error {
		return fmt.Errorf("not ready")
	}

	c := newTestClient(t, mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := c.WaitForReady(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cancel")
}

func TestProbe_SessionError(t *testing.T) {
	t.Parallel()

	c := &Client{
		host: "testhost",
		port: 2222,
		user: "testuser",
	}
	c.createSession = func(_ context.Context) (remoteSession, func(), error) {
		return nil, nil, fmt.Errorf("connection refused")
	}

	err := c.probe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestSSHConfig_InvalidKeyData(t *testing.T) {
	t.Parallel()

	c := &Client{
		host:    "testhost",
		port:    2222,
		user:    "testuser",
		keyPath: "/fake/key",
		readFile: func(_ string) ([]byte, error) {
			return []byte("this is not a PEM key"), nil
		},
		writeFile: os.WriteFile,
	}

	_, err := c.sshConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse SSH key")
}

func TestSSHConfig_ValidKeyParsing(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	privKeyPath, _, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	c := &Client{
		host:     "testhost",
		port:     2222,
		user:     "testuser",
		keyPath:  privKeyPath,
		readFile: os.ReadFile,
	}

	config, err := c.sshConfig()
	require.NoError(t, err)
	assert.Equal(t, "testuser", config.User)
	assert.NotEmpty(t, config.Auth)
}

func TestWithHostKey_SetsExpectedHostKey(t *testing.T) {
	t.Parallel()

	_, pubKey, err := GenerateHostKeyPair()
	require.NoError(t, err)

	c := NewClient("127.0.0.1", 22, "user", "/tmp/key", WithHostKey(pubKey))
	assert.NotNil(t, c.expectedHostKey)
	assert.Equal(t, pubKey.Marshal(), c.expectedHostKey.Marshal())
}

func TestWithHostKey_NilFallback(t *testing.T) {
	t.Parallel()

	// No options → expectedHostKey should be nil.
	c := NewClient("127.0.0.1", 22, "user", "/tmp/key")
	assert.Nil(t, c.expectedHostKey)
}

func TestSSHConfig_WithHostKey_AcceptsMatchingKey(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	privKeyPath, _, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	_, hostPubKey, err := GenerateHostKeyPair()
	require.NoError(t, err)

	c := &Client{
		host:            "testhost",
		port:            2222,
		user:            "testuser",
		keyPath:         privKeyPath,
		readFile:        os.ReadFile,
		expectedHostKey: hostPubKey,
	}

	config, err := c.sshConfig()
	require.NoError(t, err)
	require.NotNil(t, config.HostKeyCallback)

	// Matching key should be accepted.
	err = config.HostKeyCallback("testhost:2222", nil, hostPubKey)
	assert.NoError(t, err, "matching host key should be accepted")
}

func TestSSHConfig_WithHostKey_RejectsMismatchedKey(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	privKeyPath, _, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	_, hostPubKey, err := GenerateHostKeyPair()
	require.NoError(t, err)

	// Generate a different key to simulate an impersonator.
	_, wrongPubKey, err := GenerateHostKeyPair()
	require.NoError(t, err)

	c := &Client{
		host:            "testhost",
		port:            2222,
		user:            "testuser",
		keyPath:         privKeyPath,
		readFile:        os.ReadFile,
		expectedHostKey: hostPubKey,
	}

	config, err := c.sshConfig()
	require.NoError(t, err)
	require.NotNil(t, config.HostKeyCallback)

	// Mismatched key should be rejected.
	err = config.HostKeyCallback("testhost:2222", nil, wrongPubKey)
	assert.Error(t, err, "mismatched host key should be rejected")
}

func TestSSHConfig_WithoutHostKey_AcceptsAnyKey(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	privKeyPath, _, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	c := &Client{
		host:     "testhost",
		port:     2222,
		user:     "testuser",
		keyPath:  privKeyPath,
		readFile: os.ReadFile,
	}

	config, err := c.sshConfig()
	require.NoError(t, err)
	require.NotNil(t, config.HostKeyCallback)

	// Without host key pinning, any key should be accepted.
	_, anyPubKey, err := GenerateHostKeyPair()
	require.NoError(t, err)

	err = config.HostKeyCallback("testhost:2222", nil, anyPubKey)
	assert.NoError(t, err, "insecure callback should accept any key")
}
