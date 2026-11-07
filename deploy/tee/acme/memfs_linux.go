//go:build linux

package main

import (
	"fmt"
	"syscall"
)

// statfs f_type values from linux/magic.h.
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// onMemoryFilesystem reports whether path is on tmpfs or ramfs (D133: the certificate key is never
// written to a disk-backed filesystem).
func onMemoryFilesystem(path string) (bool, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return false, fmt.Errorf("statfs %s: %w", path, err)
	}
	switch uint32(stat.Type) {
	case tmpfsMagic, ramfsMagic:
		return true, nil
	}
	return false, nil
}
