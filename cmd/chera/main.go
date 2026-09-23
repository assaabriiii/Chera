// Command chera diagnoses why a network service is unreachable.
package main

import (
	"os"

	"github.com/assaabriiii/chera/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.Env{
		Stdout: os.Stdout,
		Out:    os.Stdout,
		Err:    os.Stderr,
	}))
}
