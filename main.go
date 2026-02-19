package main

import (
	"flag"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	dnssolver "github.com/lrx0014/cert-manager-webhook-wix/pkg/dns"
	"k8s.io/klog/v2"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	configureLogging()

	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, dnssolver.New("wix"))
}

func configureLogging() {
	klog.InitFlags(nil)
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LOG_LEVEL")), "DEBUG") {
		_ = flag.Set("v", "4")
	}
}
