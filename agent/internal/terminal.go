package internal

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

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
	CheckOrigin: sameHostOrigin,
}

func sameHostOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func isPlaceholderTerminalToken(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	return v == "changeme" ||
		v == "change-me" ||
		v == "change_me" ||
		v == "change-me-terminal-token" ||
		strings.HasPrefix(v, "change-me")
}

func terminalSharedToken() string {
	token := getenv("FLEET_TERMINAL_TOKEN", "")
	if token == "" {
		token = getenv("AGENT_TERMINAL_TOKEN", "")
	}
	if token == "" {
		token = getenv("TERM_TOKEN", "")
	}
	return strings.TrimSpace(token)
}

func terminalListenAddr() string {
	return resolveTerminalListenAddr(getenv("FLEET_TERMINAL_LISTEN", "auto:18080"))
}

func resolveTerminalListenAddr(value string) string {
	listen := strings.TrimSpace(value)
	if listen == "" {
		listen = "auto:18080"
	}
	if strings.HasPrefix(strings.ToLower(listen), "auto:") {
		parts := strings.SplitN(listen, ":", 2)
		port := ""
		if len(parts) == 2 {
			port = strings.TrimSpace(parts[1])
		}
		if port == "" {
			port = "18080"
		}
		return net.JoinHostPort(terminalSSHTarget(), port)
	}
	return listen
}

func terminalTokenFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Fleet-Terminal-Token"))
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
		return sshConsoleAvailable()
	}
}

func sshConsoleAvailable() bool {
	if commandPath("/usr/bin/ssh", "/bin/ssh", "ssh") == "" {
		return false
	}
	target := terminalSSHTarget()
	if target == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, "22"), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func loginCommand() *exec.Cmd {
	loginPath := commandPath("/bin/login", "/usr/bin/login", "login")
	agettyPath := commandPath("/sbin/agetty", "/usr/sbin/agetty", "agetty")
	if loginPath == "" {
		loginPath = "/bin/login"
	}

	if os.Geteuid() == 0 {
		if agettyPath != "" && prefersSSHConsoleBackend() {
			if self, err := os.Executable(); err == nil && self != "" {
				return exec.Command(
					agettyPath,
					"--noclear",
					"--login-program", self,
					"--login-options", "terminal-ssh-login \\u",
					"-",
					"xterm",
				)
			}
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

func terminalSSHTarget() string {
	if target := strings.TrimSpace(os.Getenv("FLEET_TERMINAL_SSH_HOST")); target != "" {
		return target
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				if v4 := ip.To4(); v4 != nil {
					return v4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

func terminalSSHCommand(username string) *exec.Cmd {
	sshPath := commandPath("/usr/bin/ssh", "/bin/ssh", "ssh")
	if sshPath == "" {
		sshPath = "ssh"
	}
	return exec.Command(
		sshPath,
		"-tt",
		"-o", "LogLevel=ERROR",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "PreferredAuthentications=password,keyboard-interactive",
		"-o", "PubkeyAuthentication=no",
		"-o", "NumberOfPasswordPrompts=3",
		username+"@"+terminalSSHTarget(),
	)
}

func RunTerminalSSHLoginFromArgs(args []string) bool {
	if len(args) < 2 || args[1] != "terminal-ssh-login" {
		return false
	}
	if len(args) < 3 {
		os.Exit(2)
	}
	username := strings.TrimSpace(args[2])
	if username == "" || strings.HasPrefix(username, "-") || strings.ContainsAny(username, "\x00\r\n") {
		os.Exit(2)
	}

	cmd := terminalSSHCommand(username)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
	return true
}

func StartTerminalServer() {
	// Terminal feature is intentionally opt-in.
	// Back-compat env var names:
	// - preferred: FLEET_TERMINAL_TOKEN (agent-side)
	// - legacy:   AGENT_TERMINAL_TOKEN (server-side name; some deploys reused it)
	// - legacy:   TERM_TOKEN (used by script.sh)
	token := terminalSharedToken()
	if token == "" {
		log.Println("Terminal server disabled (set FLEET_TERMINAL_TOKEN)")
		return
	}
	if isPlaceholderTerminalToken(token) {
		log.Println("Terminal server disabled (FLEET_TERMINAL_TOKEN is a placeholder)")
		return
	}
	listenAddr := terminalListenAddr()

	mux := http.NewServeMux()

	mux.HandleFunc("/terminal/ws", func(w http.ResponseWriter, r *http.Request) {
		got := terminalTokenFromRequest(r)
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
