package main

import (
	"testing"

	dnssolver "gitgub.com/lrx0014/cert-manager-webhook-wix/pkg/dns"
	"github.com/stretchr/testify/assert"
)

func TestMainSolverRegistration(t *testing.T) {
	solver := dnssolver.New("")
	assert.Equal(t, "wix", solver.Name())
}
