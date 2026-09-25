package main

import (
	"runtime"
	"strconv"
	"strings"
)

// Read the online logical CPUs for each sample. runtime.NumCPU is cached at
// process startup and misses CPU hot-add/hot-remove on a long-running agent.
// /proc/stat describes the host, independently of the agent's CPU affinity.
func onlineCPUCount(readFile func(string) ([]byte, error)) int {
	if data, err := readFile("/proc/stat"); err == nil {
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || !strings.HasPrefix(fields[0], "cpu") || len(fields[0]) <= 3 {
				continue
			}
			if _, err := strconv.ParseUint(fields[0][3:], 10, 32); err == nil {
				count++
			}
		}
		if count > 0 {
			return count
		}
	}
	// Preserve best-effort metrics if procfs is unavailable.
	return runtime.NumCPU()
}
