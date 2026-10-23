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

package httpcallout

import (
	"flag"
	"fmt"
	"net/http"
)

// TransportOptions tunes the fixture's receive side for large callout uploads.
type TransportOptions struct {
	H2C              bool
	MaxStreams       int
	ConnectionWindow int
	StreamWindow     int
}

// RegisterTransportFlags exposes the fixture server's HTTP/2 transport settings.
func RegisterTransportFlags(flags *flag.FlagSet) *TransportOptions {
	o := &TransportOptions{}
	flags.BoolVar(&o.H2C, "h2c", false, "accept HTTP/2 prior knowledge alongside HTTP/1.1")
	flags.IntVar(&o.MaxStreams, "http2-max-streams", 32, "maximum concurrent streams per connection")
	flags.IntVar(&o.ConnectionWindow, "http2-connection-window", 4<<20, "connection receive window in bytes")
	flags.IntVar(&o.StreamWindow, "http2-stream-window", 1<<20, "stream receive window in bytes")
	return o
}

// Configure applies validated protocol and receive-window settings before Serve.
func (o TransportOptions) Configure(server *http.Server) error {
	if o.MaxStreams < 1 || o.MaxStreams > 2147483647 {
		return fmt.Errorf("http2-max-streams must be between 1 and 2147483647")
	}
	for name, v := range map[string]int{"http2-connection-window": o.ConnectionWindow, "http2-stream-window": o.StreamWindow} {
		if v < 65535 || v > 2147483647 {
			return fmt.Errorf("%s must be between 65535 and 2147483647 bytes", name)
		}
	}
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	server.Protocols.SetUnencryptedHTTP2(o.H2C)
	server.HTTP2 = &http.HTTP2Config{
		MaxConcurrentStreams:          o.MaxStreams,
		MaxReceiveBufferPerConnection: o.ConnectionWindow,
		MaxReceiveBufferPerStream:     o.StreamWindow,
	}
	return nil
}
