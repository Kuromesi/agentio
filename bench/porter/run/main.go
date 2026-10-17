// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := command(os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func command(args []string) error {
	if len(args) == 2 && args[0] == "analyze" {
		return analyze(args[1])
	}
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: porter-bench run [flags] | analyze OUTPUT")
	}
	cfg, err := parseConfig(args[1:], os.Stderr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, err := newRunner(cfg)
	if err != nil {
		return err
	}
	return r.execute(ctx)
}
