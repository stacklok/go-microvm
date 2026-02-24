// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package logbridge

import (
	"context"
	"io"
	"log/slog"
	"sync"

	"github.com/sirupsen/logrus"
)

var once sync.Once

// RedirectLogrus replaces the global logrus output with an slog bridge so that
// libraries using logrus (notably gvisor-tap-vsock) flow through the caller's
// slog configuration instead of writing directly to stderr.
//
// Safe to call multiple times; only the first call takes effect.
func RedirectLogrus() {
	once.Do(func() {
		logrus.SetOutput(io.Discard)
		logrus.AddHook(&slogBridge{})
	})
}

// slogBridge is a logrus.Hook that forwards entries to slog.
type slogBridge struct{}

func (*slogBridge) Levels() []logrus.Level { return logrus.AllLevels }

func (*slogBridge) Fire(entry *logrus.Entry) error {
	attrs := make([]slog.Attr, 0, len(entry.Data))
	for k, v := range entry.Data {
		attrs = append(attrs, slog.Any(k, v))
	}
	slog.LogAttrs(context.Background(), logrusToSlog(entry.Level), entry.Message, attrs...)
	return nil
}

func logrusToSlog(level logrus.Level) slog.Level {
	switch level {
	case logrus.TraceLevel, logrus.DebugLevel:
		return slog.LevelDebug
	case logrus.InfoLevel:
		return slog.LevelInfo
	case logrus.WarnLevel:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}
