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

package envoy

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	agentiolog "github.com/openkruise/agentio/pkg/log"
	"net"
	"net/http"
	"net/netip"
	"time"
)

var processLog = agentiolog.New("gateway-envoy")

func infof(format string, args ...any)  { processLog.Info(fmt.Sprintf(format, args...)) }
func warnf(format string, args ...any)  { processLog.Warn(fmt.Sprintf(format, args...)) }
func errorf(format string, args ...any) { processLog.Error(fmt.Sprintf(format, args...)) }
func debugf(format string, args ...any) { processLog.Debug(fmt.Sprintf(format, args...)) }

func allIPv6(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is6() || ip.Is4In6() {
			return false
		}
	}
	return true
}

func get(address string) (*bytes.Buffer, error) { return getWithTimeout(address, 2*time.Second) }
func getWithTimeout(address string, timeout time.Duration) (*bytes.Buffer, error) {
	response, err := (&http.Client{Timeout: timeout}).Get(address)
	if err != nil {
		return nil, err
	}
	defer closeResource(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Envoy admin returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return bytes.NewBuffer(body), err
}

func closeResource(resource io.Closer) {
	if err := resource.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		processLog.Debug("resource cleanup failed", "error", err)
	}
}
