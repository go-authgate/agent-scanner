package main

import (
	"os"

	"github.com/go-authgate/agent-scanner/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
