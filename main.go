package main

import (
	"github.com/autonomic-ai/aws-okta/cmd"
)

// These are set via linker flags
var (
	Version = "dev"
)

func main() {
	// vars set by linker flags must be strings...
	cmd.Execute(Version)
}
