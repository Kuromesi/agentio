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

package gatewayagent

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPodAnnotationConfigPrecedence(t *testing.T) {
	for _, annotation := range []string{
		`{"envoyLogLevel":"debug","envoyComponentLogLevel":"misc:info","statsFlushInterval":"10s","logAsJSON":false,"concurrency":0,"metadata":{"team":"gateway"},"statsMatcher":{"inclusionSuffixes":["custom"]}}`,
		"envoyLogLevel: debug\nenvoyComponentLogLevel: misc:info\nstatsFlushInterval: 10s\nlogAsJSON: false\nconcurrency: 0\nmetadata:\n  team: gateway\nstatsMatcher:\n  inclusionSuffixes: [custom]\n",
	} {
		t.Run(annotation, func(t *testing.T) {
			t.Setenv(
				"AGENTIO_GATEWAY_CONFIG",
				`{"statsFlushInterval":"5s","logAsJSON":true,"concurrency":3,"secretTTL":"12h","metadata":{"team":"global","region":"east"},"statsMatcher":{"inclusionPrefixes":["my_cluster"]}}`,
			)
			t.Setenv("AGENTIO_CPU_LIMIT", "bad")
			t.Setenv("AGENTIO_META_team", "environment")
			path := filepath.Join(t.TempDir(), "annotations")
			content := "other.example/setting=" + strconv.Quote(
				"unrelated\nannotation",
			) + "\n" + gatewayConfigAnnotation + "=" + strconv.Quote(
				annotation,
			) + "\n"
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := loadConfig(nil, io.Discard, path)
			if err != nil {
				t.Fatal(err)
			}
			if c.LogLevel != "debug" || c.ComponentLogLevel != "misc:info" || c.StatsFlushInterval != 10*time.Second ||
				c.LogAsJSON ||
				c.Proxy.Concurrency != 0 ||
				c.SecretTTL != 12*time.Hour {
				t.Fatalf("annotation merge lost fields or explicit zero values: %+v", c)
			}
			if c.Metadata["team"] != "environment" || c.Metadata["region"] != "east" {
				t.Fatalf("metadata precedence: %v", c.Metadata)
			}
			if len(c.StatsMatcher.InclusionPrefixes) != 1 || c.StatsMatcher.InclusionPrefixes[0] != "my_cluster" ||
				len(c.StatsMatcher.InclusionSuffixes) != 1 ||
				c.StatsMatcher.InclusionSuffixes[0] != "custom" {
				t.Fatalf("nested options lost: %+v", c.StatsMatcher)
			}
			bootstrap, err := bootstrapConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			if bootstrap.GetStatsFlushInterval().AsDuration() != 10*time.Second {
				t.Fatal("annotation did not reach Envoy bootstrap")
			}
			c, err = loadConfig(
				[]string{
					"--stats-flush-interval=15s",
					"--concurrency=2",
					"--envoy-log-level=error",
					"--envoy-component-log-level=misc:critical",
				},
				io.Discard,
				path,
			)
			if err != nil || c.StatsFlushInterval != 15*time.Second || c.Proxy.Concurrency != 2 ||
				c.LogLevel != "error" ||
				c.ComponentLogLevel != "misc:critical" {
				t.Fatalf("CLI precedence: %+v, %v", c, err)
			}
		})
	}
}

func TestPodAnnotationConfigOptionalAndInvalid(t *testing.T) {
	t.Setenv("AGENTIO_GATEWAY_CONFIG", `{"statsFlushInterval":"7s"}`)
	for _, tc := range []struct {
		name    string
		content string
		missing bool
		bad     bool
	}{
		{name: "no volume", missing: true},
		{name: "unrelated annotation", content: `other="value"`},
		{name: "empty annotation", content: gatewayConfigAnnotation + `=""`},
		{name: "bad quoting", content: gatewayConfigAnnotation + `=not-quoted`, bad: true},
		{name: "unknown option", content: gatewayConfigAnnotation + "=" + strconv.Quote("statsFlshInterval: 10s"), bad: true},
		{name: "invalid YAML", content: gatewayConfigAnnotation + "=" + strconv.Quote("statsFlushInterval: ["), bad: true},
		{name: "invalid duration", content: gatewayConfigAnnotation + "=" + strconv.Quote("statsFlushInterval: invalid"), bad: true},
		{name: "nonpositive flush", content: gatewayConfigAnnotation + "=" + strconv.Quote("statsFlushInterval: 0s"), bad: true},
		{name: "reserved metadata", content: gatewayConfigAnnotation + "=" + strconv.Quote(`{"metadata":{"POD_UID":"forged"}}`), bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "annotations")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			c, err := loadConfig(nil, io.Discard, path)
			if tc.bad {
				if err == nil {
					t.Fatal("invalid annotation accepted")
				}
				return
			}
			if err != nil || c.StatsFlushInterval != 7*time.Second {
				t.Fatalf("optional annotation changed defaults: %v, %v", c.StatsFlushInterval, err)
			}
		})
	}
	_, err := loadConfig(nil, io.Discard, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "read Pod annotations") {
		t.Fatalf("read error was ignored: %v", err)
	}
}

func TestIndividualStatsAnnotations(t *testing.T) {
	t.Setenv(
		"AGENTIO_GATEWAY_CONFIG",
		`{"statsFlushInterval":"5s","extraStatTags":["base"],"statsMatcher":{"inclusionPrefixes":["global"]}}`,
	)
	path := filepath.Join(t.TempDir(), "annotations")
	annotations := map[string]string{
		"agent-config":             "statsFlushInterval: 10s\nextraStatTags: [config]\nstatsMatcher:\n  inclusionPrefixes: [config]\n  inclusionSuffixes: [keep]\nhistogramBuckets:\n  old: [1, 2]\n",
		"stats-flush-interval":     "15s",
		"stats-eviction-interval":  "30s",
		"stats-inclusion-prefixes": "http.custom,cluster.custom",
		"stats-inclusion-regexps":  "custom.*",
		"stats-inclusion-suffixes": "",
		"extra-stat-tags":          "config,custom,custom,",
		"stats-histogram-buckets":  `{"http.custom":[1,5,10]}`,
	}
	var content strings.Builder
	for key, value := range annotations {
		content.WriteString(gatewayAnnotationPrefix + key + "=" + strconv.Quote(value) + "\n")
	}
	if err := os.WriteFile(path, []byte(content.String()), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(nil, io.Discard, path)
	if err != nil {
		t.Fatal(err)
	}
	if c.StatsFlushInterval != 15*time.Second || c.StatsEvictionInterval != "30s" {
		t.Fatalf("individual intervals did not override config: %+v", c)
	}
	if !reflect.DeepEqual(
		c.StatsMatcher,
		&StatsMatcher{
			InclusionPrefixes: []string{"http.custom", "cluster.custom"},
			InclusionSuffixes: []string{"keep"},
			InclusionRegexps:  []string{"custom.*"},
		},
	) {
		t.Fatalf("matcher precedence: %+v", c.StatsMatcher)
	}
	if !reflect.DeepEqual(c.ExtraStatTags, []string{"config", "custom"}) {
		t.Fatalf("tags must append uniquely: %v", c.ExtraStatTags)
	}
	if !reflect.DeepEqual(c.HistogramBuckets, map[string][]float64{"http.custom": {1, 5, 10}}) {
		t.Fatalf("buckets must replace: %v", c.HistogramBuckets)
	}
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if b.GetStatsFlushInterval().AsDuration() != 15*time.Second ||
		b.GetStatsEvictionInterval().AsDuration() != 30*time.Second {
		t.Fatal("annotation intervals did not reach Envoy")
	}
	c, err = loadConfig([]string{"--stats-flush-interval=30s"}, io.Discard, path)
	if err != nil || c.StatsFlushInterval != 30*time.Second {
		t.Fatalf("explicit CLI override: %v, %v", c.StatsFlushInterval, err)
	}
}

func TestInvalidIndividualStatsAnnotations(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value string
	}{
		{"stats-flush-interval", ""}, {"stats-flush-interval", "oops"}, {"stats-flush-interval", "0s"},
		{"stats-eviction-interval", "7s"}, {"stats-histogram-buckets", "bad"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv("AGENTIO_GATEWAY_CONFIG", `{"statsFlushInterval":"5s"}`)
			path := filepath.Join(t.TempDir(), "annotations")
			if err := os.WriteFile(
				path,
				[]byte(gatewayAnnotationPrefix+tc.key+"="+strconv.Quote(tc.value)),
				0600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(nil, io.Discard, path); err == nil {
				t.Fatal("invalid stats annotation accepted")
			}
		})
	}
}
