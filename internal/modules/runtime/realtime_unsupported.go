//go:build !linux

package runtime

import (
	"context"
	"errors"
)

type unsupportedRealtimeFileMonitor struct{}

func newRealtimeFileMonitor(paths []string) realtimeFileMonitor {
	return unsupportedRealtimeFileMonitor{}
}

func (unsupportedRealtimeFileMonitor) Start(context.Context, func(FileChange)) error {
	return errors.New("real-time file monitor requires linux inotify")
}

func (unsupportedRealtimeFileMonitor) Close() error {
	return nil
}
