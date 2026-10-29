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

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func serveOrigin(ctx context.Context, address, statsAddress string) (result error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}()
	statsListener, err := net.Listen("tcp", statsAddress)
	if err != nil {
		return err
	}
	var counts sync.Map
	mux := http.NewServeMux()
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, _ *http.Request) {
		values := map[string]uint64{}
		counts.Range(func(k, v any) bool {
			values[k.(string)] = v.(*atomic.Uint64).Load()
			return true
		})
		if err := json.NewEncoder(w).Encode(values); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() {
		err := server.Serve(statsListener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
	}()
	defer func() { result = errors.Join(result, server.Close(), <-done) }()
	// Closing the listener wakes Accept; active handlers close through their context hook.
	stopped := context.AfterFunc(ctx, func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintln(os.Stderr, err)
		}
	})
	defer stopped()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			stop := context.AfterFunc(ctx, func() {
				if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					fmt.Fprintln(os.Stderr, err)
				}
			})
			defer stop()
			defer func() {
				if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					fmt.Fprintln(os.Stderr, err)
				}
			}()
			if err := transferOrigin(conn, &counts); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}
}

func transferOrigin(conn net.Conn, counts *sync.Map) error {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	} // Readiness probes and canceled streams have no command.
	fields := strings.Fields(line)
	if len(fields) != 2 || (fields[0] != "D" && fields[0] != "U") {
		return fmt.Errorf("invalid transfer command %q", line)
	}
	counter := new(atomic.Uint64)
	counts.Store(fields[1], counter)
	buf := make([]byte, 65536)
	for {
		if fields[0] == "D" {
			_, err = conn.Write(buf)
		} else {
			var n int
			n, err = reader.Read(buf)
			counter.Add(uint64(n))
		}
		if err != nil {
			return nil
		} // Infinite transfers end by client cancellation or EOF.
	}
}
