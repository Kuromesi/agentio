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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const gatewayAnnotationPrefix = "gateway.agentio.kruise.io/"

// applyPodAnnotations follows pilot-agent's environment < proxy annotation <
// individual stats annotation precedence. Explicit CLI flags are applied later.
//
//nolint:gocyclo // Keep the annotation precedence and individual overrides together.
func applyPodAnnotations(path string, options *RuntimeOptions) error {
	data, err := os.ReadFile(path)
	// Local agent invocations need not have a Kubernetes Downward API mount.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Pod annotations: %w", err)
	}
	annotations := map[string]string{}
	// Downward API serializes each entry as key=strconv.Quote(value).
	for line := range strings.SplitSeq(string(data), "\n") {
		key, quoted, found := strings.Cut(line, "=")
		if !found || !strings.HasPrefix(key, gatewayAnnotationPrefix) {
			continue
		}
		value, err := strconv.Unquote(quoted)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		annotations[key] = value
	}
	if raw := annotations[gatewayConfigAnnotation]; strings.TrimSpace(raw) != "" {
		if err := decodeRuntimeOptions(raw, gatewayConfigAnnotation, options); err != nil {
			return err
		}
	}
	for _, setting := range []struct {
		name   string
		target *string
	}{
		{"stats-flush-interval", &options.StatsFlushInterval},
		{"stats-eviction-interval", &options.StatsEvictionInterval},
	} {
		if value, found := annotations[gatewayAnnotationPrefix+setting.name]; found {
			if _, err := time.ParseDuration(value); err != nil {
				return fmt.Errorf("%s%s: %w", gatewayAnnotationPrefix, setting.name, err)
			}
			*setting.target = value
		}
	}
	for _, name := range []string{"stats-inclusion-prefixes", "stats-inclusion-suffixes", "stats-inclusion-regexps"} {
		raw := annotations[gatewayAnnotationPrefix+name]
		// Like pilot-agent, an empty individual matcher annotation leaves config intact.
		if raw == "" {
			continue
		}
		if options.StatsMatcher == nil {
			options.StatsMatcher = &StatsMatcher{}
		}
		values := strings.Split(raw, ",")
		switch name {
		case "stats-inclusion-prefixes":
			options.StatsMatcher.InclusionPrefixes = values
		case "stats-inclusion-suffixes":
			options.StatsMatcher.InclusionSuffixes = values
		case "stats-inclusion-regexps":
			options.StatsMatcher.InclusionRegexps = values
		}
	}
	if raw, found := annotations[gatewayAnnotationPrefix+"stats-histogram-buckets"]; found {
		var buckets map[string][]float64
		if err := json.Unmarshal([]byte(raw), &buckets); err != nil {
			return fmt.Errorf("%sstats-histogram-buckets: %w", gatewayAnnotationPrefix, err)
		}
		options.HistogramBuckets = buckets
	}
	if raw := annotations[gatewayAnnotationPrefix+"extra-stat-tags"]; raw != "" {
		for tag := range strings.SplitSeq(raw, ",") {
			if tag != "" && !slices.Contains(options.ExtraStatTags, tag) {
				options.ExtraStatTags = append(options.ExtraStatTags, tag)
			}
		}
	}
	return nil
}
