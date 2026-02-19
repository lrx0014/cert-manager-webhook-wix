package main

import (
	"os"

	dnssolver "github.com/lrx0014/cert-manager-webhook-wix/pkg/dns"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, dnssolver.New(""))
}
