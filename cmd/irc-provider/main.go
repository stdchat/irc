package main

import (
	"fmt"
	"os"

	"github.com/stdchat/irc"
	"stdchat.org/provider"
	"stdchat.org/service"
)

func main() {
	err := provider.Run(irc.Protocol,
		func(t service.Transporter) service.Servicer {
			return irc.NewService(t)
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
