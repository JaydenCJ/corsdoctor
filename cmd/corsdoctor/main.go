// Command corsdoctor explains exactly why a CORS request fails, by running
// the Fetch-standard CORS algorithm over a captured request and response.
package main

import (
	"os"

	"github.com/JaydenCJ/corsdoctor/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
