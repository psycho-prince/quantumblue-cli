package server

import (
	"fmt"
	"net/http"
)

// StartServer initializes a basic HTTP daemon for the CLI
func StartServer(port string) error {
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		// Placeholder for triggering scanner logic
		fmt.Fprintf(w, "Scan triggered remotely\n")
	})

	fmt.Printf("Starting QuantumBlue Daemon on port %s...\n", port)
	return http.ListenAndServe(":"+port, nil)
}
