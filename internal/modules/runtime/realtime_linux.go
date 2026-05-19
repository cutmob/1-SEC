//go:build linux

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type linuxRealtimeFileMonitor struct {
	paths []string
	fd    int
	mu    sync.Mutex
	wds   map[int]string
}

func newRealtimeFileMonitor(paths []string) realtimeFileMonitor {
	return &linuxRealtimeFileMonitor{
		paths: paths,
		fd:    -1,
		wds:   make(map[int]string),
	}
}

func (m *linuxRealtimeFileMonitor) Start(ctx context.Context, emit func(FileChange)) error {
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		return err
	}
	m.fd = fd

	for _, root := range m.paths {
		_ = m.addRecursive(root)
	}
	if len(m.wds) == 0 {
		_ = syscall.Close(fd)
		m.fd = -1
		return errors.New("no real-time watch paths available")
	}

	go m.readLoop(ctx, fd, emit)
	return nil
}

func (m *linuxRealtimeFileMonitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fd < 0 {
		return nil
	}
	err := syscall.Close(m.fd)
	m.fd = -1
	m.wds = make(map[int]string)
	return err
}

func (m *linuxRealtimeFileMonitor) addRecursive(root string) error {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return err
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		_ = m.addWatch(path)
		return nil
	})
}

func (m *linuxRealtimeFileMonitor) addWatch(path string) error {
	mask := uint32(syscall.IN_CREATE | syscall.IN_MODIFY | syscall.IN_CLOSE_WRITE |
		syscall.IN_MOVED_TO | syscall.IN_MOVED_FROM | syscall.IN_DELETE |
		syscall.IN_ATTRIB | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF)
	wd, err := syscall.InotifyAddWatch(m.fd, path, mask)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.wds[wd] = path
	m.mu.Unlock()
	return nil
}

func (m *linuxRealtimeFileMonitor) readLoop(ctx context.Context, fd int, emit func(FileChange)) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			_ = m.Close()
			return
		default:
		}

		n, err := syscall.Read(fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				select {
				case <-ctx.Done():
					_ = m.Close()
					return
				default:
					syscall.Select(0, nil, nil, nil, &syscall.Timeval{Usec: 50_000})
					continue
				}
			}
			return
		}
		m.parseEvents(buf[:n], emit)
	}
}

func (m *linuxRealtimeFileMonitor) parseEvents(buf []byte, emit func(FileChange)) {
	const eventSize = int(unsafe.Sizeof(syscall.InotifyEvent{}))
	for offset := 0; offset+eventSize <= len(buf); {
		raw := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		offset += eventSize
		if offset+int(raw.Len) > len(buf) {
			break
		}

		name := strings.TrimRight(string(buf[offset:offset+int(raw.Len)]), "\x00")
		offset += int(raw.Len)

		m.mu.Lock()
		dir := m.wds[int(raw.Wd)]
		m.mu.Unlock()
		if dir == "" {
			continue
		}
		path := dir
		if name != "" {
			path = filepath.Join(dir, name)
		}

		if raw.Mask&syscall.IN_ISDIR != 0 && (raw.Mask&syscall.IN_CREATE != 0 || raw.Mask&syscall.IN_MOVED_TO != 0) {
			_ = m.addRecursive(path)
		}

		if changeType := inotifyChangeType(raw.Mask); changeType != "" {
			emit(FileChange{Path: path, Type: changeType})
		}
	}
}

func inotifyChangeType(mask uint32) string {
	switch {
	case mask&syscall.IN_CREATE != 0:
		return "created"
	case mask&syscall.IN_CLOSE_WRITE != 0:
		return "close_write"
	case mask&syscall.IN_MODIFY != 0:
		return "modified"
	case mask&syscall.IN_MOVED_TO != 0:
		return "moved_to"
	case mask&syscall.IN_MOVED_FROM != 0:
		return "moved_from"
	case mask&syscall.IN_DELETE != 0:
		return "deleted"
	case mask&syscall.IN_ATTRIB != 0:
		return "attrib"
	default:
		return ""
	}
}
