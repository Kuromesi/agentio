// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package envoy

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

func infof(format string, args ...any)  { slog.Info(fmt.Sprintf(format, args...)) }
func warnf(format string, args ...any)  { slog.Warn(fmt.Sprintf(format, args...)) }
func errorf(format string, args ...any) { slog.Error(fmt.Sprintf(format, args...)) }
func debugf(format string, args ...any) { slog.Debug(fmt.Sprintf(format, args...)) }

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

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
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Envoy admin returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return bytes.NewBuffer(body), err
}
