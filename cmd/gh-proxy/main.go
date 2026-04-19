// Command gh-proxy is the entrypoint for the gh-proxy server and tooling.
package main

import (
	"fmt"
	"os"

	"github.com/denysvitali/gh-proxy/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
