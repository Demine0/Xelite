package main

import "golang.org/x/sys/windows"

// waitForProcess blocks until the process with the given PID exits.
// It reports false if the process could not be watched.
func waitForProcess(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	windows.WaitForSingleObject(h, windows.INFINITE)
	return true
}
