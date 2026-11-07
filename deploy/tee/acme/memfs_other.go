//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

// onMemoryFilesystem cannot tell tmpfs apart outside Linux; gray-acme only runs in the Linux image,
// and the tests replace this check.
func onMemoryFilesystem(path string) (bool, error) {
	return false, fmt.Errorf("cannot tell whether %s is a tmpfs on %s", path, runtime.GOOS)
}
