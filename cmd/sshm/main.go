package main

import (
	"fmt"
	"os"

	"github.com/michael-ltm/sshm/internal/commands"
)

func main() {
	if err := commands.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
