//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"
)

// waitForProcess blocks until the process with the given PID exits.
// It reports false if the process could not be watched.
func waitForProcess(pid int) bool {
	for {
		p, err := os.FindProcess(pid)
		if err != nil || p.Signal(syscall.Signal(0)) != nil {
			return true
		}
		time.Sleep(2 * time.Second)
	}
}
