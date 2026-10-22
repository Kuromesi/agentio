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
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/runnable"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestAuditWebhookVerifiesTLSByDefault(t *testing.T) {
	configured := flag.Lookup("audit-webhook-insecure-skip-verify")
	if configured == nil {
		t.Fatal("audit webhook TLS verification flag is not registered")
	}
	if configured.DefValue != "false" {
		t.Fatalf("audit webhook insecure-skip-verify default = %q, want false", configured.DefValue)
	}
}

func TestPrintEnvironmentExitsBeforeStartup(t *testing.T) {
	if os.Getenv("EPE_ENV_DOC_TEST_HELPER") == "true" {
		// Run in a subprocess because EPE owns the process-global flag set.
		os.Args = []string{"epe", "-print-env", "-print-env-format=" + os.Getenv("EPE_ENV_DOC_TEST_FORMAT")}
		flag.CommandLine = flag.NewFlagSet("epe", flag.ContinueOnError)
		if err := run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, format := range []string{"text", "markdown"} {
		command := exec.Command(os.Args[0], "-test.run=^TestPrintEnvironmentExitsBeforeStartup$")
		command.Env = append(os.Environ(), "EPE_ENV_DOC_TEST_HELPER=true", "EPE_ENV_DOC_TEST_FORMAT="+format,
			"CREDENTIAL_PROVIDER_MTLS_SOURCE=invalid", "KUBECONFIG=/does/not/exist")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s export attempted startup: %v\n%s", format, err, output)
		}
		for _, expected := range []string{"IDENTITY_PROVIDER_URL", "TOKEN_CACHE_TTL", "TOKEN_CACHE_MAX_SIZE",
			"CREDENTIAL_CACHE_INVALIDATION_WINDOW", "CREDENTIAL_CACHE_INVALIDATION_MAX_TTL", "STS_CACHE_MAX_SIZE", "CREDENTIAL_PROVIDER_MTLS_SOURCE", "AUDIT_WEBHOOK_DIAL_TIMEOUT",
			"HTTP_CALLOUT_MAX_RESPONSE_BYTES"} {
			if !strings.Contains(string(output), expected) {
				t.Errorf("%s export missing %s", format, expected)
			}
		}
		if format == "markdown" && strings.Contains(string(output), "AGENTIO_CA_SECRET_NAME") {
			t.Fatal("EPE table includes unrelated control-plane settings")
		}
	}
}

// startupCache exposes when startup reaches each cache without timer-based assertions.
type startupCache struct {
	synced  chan struct{}
	waiting chan struct{}
}

func (c startupCache) HasSynced() bool {
	select {
	case <-c.synced:
		return true
	default:
		return false
	}
}

func (c startupCache) WaitUntilSynced(stop <-chan struct{}) bool {
	close(c.waiting)
	select {
	case <-c.synced:
		return true
	case <-stop:
		return false
	}
}

func TestExtProcWaitsForInitialCaches(t *testing.T) {
	for _, cancelAtSecret := range []bool{false, true} {
		name := "synced"
		if cancelAtSecret {
			name = "cancelled"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			caches := make([]krt.Syncer, 3)
			for i := range caches {
				caches[i] = startupCache{synced: make(chan struct{}), waiting: make(chan struct{})}
			}
			started := make(chan struct{})
			server := runnable.Func(func(context.Context) error {
				close(started)
				return nil
			})
			done := make(chan error, 1)
			go func() { done <- startExtProc(ctx, server, caches...) }()
			for i, cache := range caches {
				c := cache.(startupCache)
				select {
				case <-c.waiting:
				case <-ctx.Done():
					t.Fatal("startup did not reach cache", i)
				}
				select {
				case <-started:
					t.Fatal("ext-proc started before cache synchronized", i)
				default:
				}
				if cancelAtSecret && i == len(caches)-1 {
					cancel()
				} else {
					close(c.synced)
				}
			}
			select {
			case err := <-done:
				if cancelAtSecret {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("startup error = %v, want cancellation", err)
					}
					select {
					case <-started:
						t.Fatal("ext-proc started after synchronization was cancelled")
					default:
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					select {
					case <-started:
					default:
						t.Fatal("ext-proc did not start after synchronization")
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("startup did not finish")
			}
		})
	}
}

func TestTokenSecretNamespace(t *testing.T) {
	for _, tc := range []struct {
		namespace string
		scope     string
		want      string
		wantErr   bool
	}{
		{"custom-system", "system", "custom-system", false},
		{"custom-system", "cluster", "", false},
		{"custom-system", "", "", true},
		{"custom-system", "Cluster", "", true},
		{"", "system", "", true},
		{"", "cluster", "", true},
	} {
		t.Run(tc.namespace+"/"+tc.scope, func(t *testing.T) {
			got, err := tokenSecretNamespace(tc.namespace, tc.scope)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("tokenSecretNamespace = %q, %v; want %q, error=%t", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestSystemNamespaceFlag(t *testing.T) {
	if os.Getenv("EPE_NAMESPACE_TEST_HELPER") == "true" {
		if err := flag.CommandLine.Parse(strings.Fields(os.Getenv("EPE_NAMESPACE_TEST_ARGS"))); err != nil {
			t.Fatal(err)
		}
		if *systemNamespace != os.Getenv("EPE_NAMESPACE_TEST_WANT") || *secretWatchScope != "system" {
			t.Fatalf("namespace=%q scope=%q", *systemNamespace, *secretWatchScope)
		}
		return
	}
	for _, tc := range []struct {
		name string
		args string
		want string
	}{
		{"pod namespace", "", "pod-system"},
		{"explicit namespace", "--namespace=explicit-system", "explicit-system"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "pod-system")
			command := exec.Command(os.Args[0], "-test.run=^TestSystemNamespaceFlag$")
			command.Env = append(os.Environ(), "EPE_NAMESPACE_TEST_HELPER=true",
				"EPE_NAMESPACE_TEST_ARGS="+tc.args, "EPE_NAMESPACE_TEST_WANT="+tc.want)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("namespace flag: %v\n%s", err, output)
			}
		})
	}
}
