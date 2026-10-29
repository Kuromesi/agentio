// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// CONNECT load generator and TCP origin; designed for a Linux process namespace.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type config struct {
	Streams      int
	Connections  int
	Direction    string
	Distinct     bool
	FastStream   bool
	Duration     time.Duration
	Warmup       time.Duration
	SetupTimeout time.Duration
	Target       string
	Origin       string
	Stats        string
	EnvoyPID     int
	OriginPID    int
	Ticks        float64
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := command(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func command(ctx context.Context, args []string) error {
	originMode := len(args) > 0 && args[0] == "origin"
	if originMode {
		args = args[1:]
	}
	c, err := parseConfig(args)
	if err != nil {
		return err
	}
	if originMode {
		return serveOrigin(ctx, c.Origin, c.Stats)
	}
	result, err := runLoad(ctx, c)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func parseConfig(args []string) (config, error) {
	c := config{}
	f := flag.NewFlagSet("connect-load [origin]", flag.ContinueOnError)
	f.IntVar(&c.Streams, "streams", 1, "concurrent CONNECT streams")
	f.IntVar(&c.Connections, "connections", 4, "maximum outer HTTP/2 connections")
	f.StringVar(&c.Direction, "direction", "D", "D or U")
	f.BoolVar(&c.Distinct, "distinct", false, "one sandbox per stream")
	f.BoolVar(&c.FastStream, "fast-stream", false, "last stream uses the fast sandbox")
	f.DurationVar(&c.Duration, "duration", 6*time.Second, "measurement window")
	f.DurationVar(&c.Warmup, "warmup", 2*time.Second, "warmup before measuring")
	f.DurationVar(&c.SetupTimeout, "setup-timeout", 30*time.Second, "CONNECT establishment deadline")
	f.StringVar(&c.Target, "target", "127.0.0.1:17902", "plaintext HTTP/2 CONNECT listener")
	f.StringVar(&c.Origin, "origin", "127.0.0.1:17900", "TCP origin listen address")
	f.StringVar(&c.Stats, "stats", "127.0.0.1:17903", "origin HTTP counter listen address")
	f.IntVar(&c.EnvoyPID, "envoy-pid", 0, "Envoy PID in this process namespace")
	f.IntVar(&c.OriginPID, "origin-pid", 0, "origin PID in this process namespace")
	f.Float64Var(&c.Ticks, "ticks", 100, "Linux CLK_TCK, runner obtains this with getconf")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 || c.Streams <= 0 || c.Connections <= 0 || c.Duration <= 0 || c.Warmup < 0 ||
		c.SetupTimeout <= 0 ||
		c.Ticks <= 0 ||
		(c.Direction != "D" && c.Direction != "U") {
		return c, fmt.Errorf(
			"invalid arguments: require positive counts/durations/ticks, nonnegative warmup, direction D or U",
		)
	}
	return c, nil
}
