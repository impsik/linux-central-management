package main

import (
	"errors"
	"runtime"
	"testing"
)

func TestOnlineCPUCountTracksHotplugWithoutAgentRestart(t *testing.T) {
	stat := ""
	read := func(path string) ([]byte, error) {
		if path != "/proc/stat" {
			t.Fatalf("unexpected path: %s", path)
		}
		return []byte(stat), nil
	}
	for _, sample := range []struct {
		stat string
		want int
	}{
		{"cpu 40 0 0 80\ncpu0 20 0 0 40\ncpu1 20 0 0 40\nintr 123\n", 2},
		{"cpu 40 0 0 80\ncpu0 20 0 0 40\ncpu1 20 0 0 40\ncpu2 0 0 0 0\ncpu3 0 0 0 0\n", 4},
		{"cpu 40 0 0 80\ncpu0 20 0 0 40\ncpu1 20 0 0 40\ncpu2 0 0 0 0\ncpu3 0 0 0 0\ncpu4 0 0 0 0\ncpu5 0 0 0 0\n", 6},
		// Offline CPU IDs need not be contiguous. Count rows, not the max ID.
		{"cpu 40 0 0 80\ncpu0 20 0 0 40\ncpu3 20 0 0 40\n", 2},
	} {
		stat = sample.stat
		if got := onlineCPUCount(read); got != sample.want {
			t.Fatalf("online CPU count = %d, want %d", got, sample.want)
		}
	}
}

func TestOnlineCPUCountFallsBackWhenProcfsIsUnavailable(t *testing.T) {
	for _, sample := range []struct {
		data string
		err  error
	}{
		{"", errors.New("procfs unavailable")},
		{"", nil},
		{"cpu 40 0 0 80\ncpu_invalid 1 2 3\nintr 123\n", nil},
	} {
		got := onlineCPUCount(func(string) ([]byte, error) { return []byte(sample.data), sample.err })
		if got != runtime.NumCPU() {
			t.Fatalf("fallback CPU count = %d, want %d", got, runtime.NumCPU())
		}
	}
}
