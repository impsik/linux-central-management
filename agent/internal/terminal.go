package internal

import (
	"log"
	"net/http"
	"os"
	"os/exec"

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

func StartTerminalServer() {
	token := getenv("FLEET_TERMINAL_TOKEN", "")
	if token == "" {
		log.Println("Terminal server disabled (FLEET_TERMINAL_TOKEN not set)")
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

		// VMware-console style: always present a real login prompt.
		// If the agent isn't running as root, try via passwordless sudo.
		var cmd *exec.Cmd
		if os.Geteuid() == 0 {
			cmd = exec.Command("/bin/login")
		} else {
			cmd = exec.Command("sudo", "-n", "/bin/login")
		}
		ptmx, err := pty.Start(cmd)
		if err != nil {
			// Best-effort error to the client before closing.
			conn.WriteMessage(websocket.TextMessage, []byte("[ERROR] Cannot start login. Ensure agent runs as root or allow sudo NOPASSWD for /bin/login.\r\n"))
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
