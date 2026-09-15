package main

import (
	"context"
	"testing"
)

func TestUserControlRejectsOptionsAndRootBeforeRunningCommands(t *testing.T) {
	for _, username := range []string{"", "-a", "--all", "bad\nuser", "name:password", "root"} {
		for _, action := range []string{"user-lock", "user-unlock"} {
			out, _, code, msg := controlUser(context.Background(), username, action)
			if code == 0 || msg == "" || out != "" {
				t.Fatalf("unsafe account operation: %q %q: %s %s", username, action, out, msg)
			}
		}
	}
}
