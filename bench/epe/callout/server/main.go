// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/openkruise/agentio/bench/epe/callout"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "HTTP listen address")
	flag.Parse()
	server := &http.Server{
		Addr:              *listen,
		Handler:           &callout.Handler{},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      65 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	log.Printf("httpcallout test server listening on %s", *listen)
	log.Fatal(server.ListenAndServe())
}
