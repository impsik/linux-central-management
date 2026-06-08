package internal

import (
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

var upgrader = websocket.Upgrader{
	// NOTE: Origin checks are not a security boundary on their own for non-browser clients.
	// We also require an explicit token.
	CheckOrigin: func(r *http.Request) bool { return true },
}

func commandPath(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

func osReleaseID() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "ID=")), "\"")
		}
	}
	return ""
}

func prefersSSHConsoleBackend() bool {
	backend := strings.ToLower(strings.TrimSpace(getenv("FLEET_TERMINAL_BACKEND", "auto")))
	if backend == "ssh" {
		return true
	}
	if backend == "login" {
		return false
	}
	switch strings.ToLower(osReleaseID()) {
	case "rhel", "redhat", "rocky", "almalinux", "centos", "fedora":
		return true
	default:
		return false
	}
}

func loginCommand() *exec.Cmd {
	loginPath := commandPath("/bin/login", "/usr/bin/login", "login")
	agettyPath := commandPath("/sbin/agetty", "/usr/sbin/agetty", "agetty")
	sshPath := commandPath("/usr/bin/ssh", "/bin/ssh", "ssh")
	if loginPath == "" {
		loginPath = "/bin/login"
	}

	if os.Geteuid() == 0 {
		if agettyPath != "" && sshPath != "" && prefersSSHConsoleBackend() {
			return exec.Command(
				agettyPath,
				"--noclear",
				"--login-program", sshPath,
				"--login-options", "-tt -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=keyboard-interactive,password -o PubkeyAuthentication=no \\u@localhost",
				"-",
				"xterm",
			)
		}
		if agettyPath != "" {
			return exec.Command(agettyPath, "--noclear", "--login-program", loginPath, "-", "xterm")
		}
		return exec.Command(loginPath)
	}
	if agettyPath != "" {
		return exec.Command("sudo", "-n", agettyPath, "--noclear", "--login-program", loginPath, "-", "xterm")
	}
	return exec.Command("sudo", "-n", loginPath)
}

func StartTerminalServer() {
	// Terminal feature is intentionally opt-in.
	// Back-compat env var names:
	// - preferred: FLEET_TERMINAL_TOKEN (agent-side)
	// - legacy:   AGENT_TERMINAL_TOKEN (server-side name; some deploys reused it)
	// - legacy:   TERM_TOKEN (used by script.sh)
	token := getenv("FLEET_TERMINAL_TOKEN", "")
	if token == "" {
		token = getenv("AGENT_TERMINAL_TOKEN", "")
	}
	if token == "" {
		token = getenv("TERM_TOKEN", "")
	}
	if token == "" {
		log.Println("Terminal server disabled (set FLEET_TERMINAL_TOKEN)")
		return
	}
	listenAddr := getenv("FLEET_TERMINAL_LISTEN", "0.0.0.0:18080")

	mux := http.NewServeMux()

	mux.HandleFunc("/terminal/ws", func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Fleet-Terminal-Token")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if got != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// VMware-console style: always present a real login prompt. agetty is
		// preferred because direct login(1) can attach silently on some RHEL PTYs.
		cmd := loginCommand()
		ptmx, err := pty.Start(cmd)
		if err != nil {
			// Best-effort error to the client before closing.
			conn.WriteMessage(websocket.TextMessage, []byte("[ERROR] Cannot start login. Ensure agent runs as root or allow sudo NOPASSWD for login/agetty.\r\n"))
			return
		}
		defer ptmx.Close()

		// PTY → Browser
		go func() {
			buf := make([]byte, 8192)
			for {
				n, err := ptmx.Read(buf)
				if err != nil {
					break
				}
				conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
		}()

		// Browser → PTY
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			ptmx.Write(msg)
		}
	})

	log.Printf("Terminal listening on %s/terminal/ws", listenAddr)
	go http.ListenAndServe(listenAddr, mux)
}
