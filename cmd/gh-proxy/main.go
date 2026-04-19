package main

import (
	"fmt"
	"os"

	"github.com/kaiko-ai/gh-proxy/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
